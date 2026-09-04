//! SPEC-0073 §18/§19 — `O_DIRECT` para caminhos BULK, com fallback transparente.
//!
//! A §18 é inequívoca sobre onde isto pode e não pode entrar:
//!
//! ```text
//! candidatos:      cold tier, large compaction, backup, bulk export, bulk restore
//! NÃO usar para:   hot WAL, small random queries, metadata, manifest, cursor, checkpoint
//! ```
//!
//! A lista proibida não é conservadorismo: `O_DIRECT` contorna o page cache, e
//! para um WAL isso troca uma escrita que o kernel agrega por uma escrita
//! síncrona alinhada por registo. Para uma leitura de manifesto de 200 bytes,
//! obriga a ler um bloco inteiro para um buffer alinhado. Nos dois casos perde,
//! e no primeiro perde no caminho de durabilidade.
//!
//! ## O que a §19 exige, e o que aqui está
//!
//! | requisito | onde |
//! |---|---|
//! | alinhamento de buffer | [`BufferAlinhado`] — alocação alinhada ao bloco lógico |
//! | alinhamento de offset | [`alinhado`], verificado antes de cada operação |
//! | alinhamento de tamanho | idem |
//! | filesystem constraints | o bloco lógico vem do dispositivo, não é adivinhado |
//! | fallback transparente | [`abrir_bulk`] devolve buffered quando o directo falha |
//!
//! `EINVAL` é o erro que o kernel devolve para *qualquer* violação de
//! alinhamento e também para "este sistema de ficheiros não suporta O_DIRECT" —
//! são indistinguíveis a partir do errno. Por isso o fallback não tenta
//! adivinhar qual foi: volta a buffered e diz porquê.

use std::fs::File;
use std::io;
use std::path::Path;

/// Alinhamento por omissão quando o bloco lógico do dispositivo não se deixa
/// ler. 4096 é o bloco lógico de praticamente todo o armazenamento moderno, e
/// é o valor que o `O_DIRECT` do Linux exige na esmagadora maioria dos casos.
pub const ALINHAMENTO_PADRAO: usize = 4096;

/// Como o ficheiro acabou por ser aberto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModoBulk {
    /// `O_DIRECT` activo, com este alinhamento.
    Directo { alinhamento: usize },
    /// Buffered, e porquê — nunca um fallback mudo.
    Buffered { motivo: String },
}

impl ModoBulk {
    pub fn e_directo(&self) -> bool {
        matches!(self, Self::Directo { .. })
    }

    /// O alinhamento a respeitar. Em buffered não há nenhum, e 1 diz isso sem
    /// obrigar o chamador a um `match`.
    pub fn alinhamento(&self) -> usize {
        match self {
            Self::Directo { alinhamento } => *alinhamento,
            Self::Buffered { .. } => 1,
        }
    }
}

/// Um ficheiro aberto para I/O bulk, com o modo que se conseguiu.
#[derive(Debug)]
pub struct FicheiroBulk {
    pub file: File,
    pub modo: ModoBulk,
}

/// `valor` é múltiplo de `alinhamento`?
pub fn alinhado(valor: u64, alinhamento: usize) -> bool {
    alinhamento <= 1 || valor.is_multiple_of(alinhamento as u64)
}

/// Abre um ficheiro para leitura bulk, tentando `O_DIRECT` e caindo para
/// buffered sem falhar.
///
/// O fallback é a §19 aplicada: "qualquer erro como EINVAL, unsupported
/// filesystem ou alignment violation MUST permitir fallback seguro para
/// buffered I/O". Uma exportação para o lakehouse não pode falhar porque o
/// sistema de ficheiros de destino não suporta uma optimização.
pub fn abrir_bulk(caminho: &Path) -> io::Result<FicheiroBulk> {
    #[cfg(target_os = "linux")]
    {
        let alinhamento = bloco_logico(caminho).unwrap_or(ALINHAMENTO_PADRAO);
        match abrir_directo(caminho) {
            Ok(file) => {
                return Ok(FicheiroBulk {
                    file,
                    modo: ModoBulk::Directo { alinhamento },
                })
            }
            Err(erro) => {
                // Não distinguimos EINVAL de "fs não suporta": o kernel usa o
                // mesmo errno para os dois, e adivinhar qual foi só produziria
                // uma mensagem confiante e possivelmente errada.
                let motivo = format!("O_DIRECT recusado ({erro}); buffered");
                return Ok(FicheiroBulk {
                    file: File::open(caminho)?,
                    modo: ModoBulk::Buffered { motivo },
                });
            }
        }
    }
    #[allow(unreachable_code)]
    Ok(FicheiroBulk {
        file: File::open(caminho)?,
        modo: ModoBulk::Buffered {
            motivo: "O_DIRECT só existe em Linux".into(),
        },
    })
}

#[cfg(target_os = "linux")]
fn abrir_directo(caminho: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECT)
        .open(caminho)
}

/// O bloco lógico do dispositivo que contém o ficheiro.
///
/// Sai de `/sys/block/<dev>/queue/logical_block_size`. Adivinhar 4096 funciona
/// quase sempre e falha exactamente nos dispositivos onde falhar dói — os de
/// 512 bytes ficariam com um alinhamento mais folgado do que o necessário (o
/// que é seguro), e um hipotético de 8192 ficaria com um alinhamento
/// INSUFICIENTE, que é `EINVAL` em cada operação.
#[cfg(target_os = "linux")]
fn bloco_logico(caminho: &Path) -> Option<usize> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(caminho).ok()?;
    let dev = meta.dev();
    // major:minor do dispositivo. `libc::major`/`minor` não são estáveis em
    // todas as versões, e a aritmética é a documentada em `makedev(3)`.
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff);
    let minor = (dev & 0xff) | ((dev >> 12) & !0xff);
    let nome = std::fs::read_link(format!("/sys/dev/block/{major}:{minor}")).ok()?;
    let nome = nome.file_name()?.to_str()?.to_string();
    // Uma partição (`sda1`) herda a fila do disco (`sda`); o sysfs da partição
    // não tem `queue/`.
    for candidato in [
        format!("/sys/block/{nome}/queue/logical_block_size"),
        format!("/sys/class/block/{nome}/../queue/logical_block_size"),
    ] {
        if let Ok(texto) = std::fs::read_to_string(&candidato) {
            if let Ok(n) = texto.trim().parse::<usize>() {
                if n.is_power_of_two() && n >= 512 {
                    return Some(n);
                }
            }
        }
    }
    None
}

/// Um buffer cujo endereço inicial é múltiplo do alinhamento pedido.
///
/// `Vec<u8>` cai onde o alocador quiser, e `O_DIRECT` exige que o endereço do
/// buffer — não só o offset e o tamanho — esteja alinhado. É o mesmo tipo de
/// erro que o `advise_slice` tinha com o `madvise`: entregar ao kernel um
/// ponteiro que ele recusa, e receber `EINVAL` sem perceber porquê.
pub struct BufferAlinhado {
    dados: Vec<u8>,
    inicio: usize,
    tamanho: usize,
}

impl BufferAlinhado {
    /// Reserva `tamanho` bytes utilizáveis, começando num endereço alinhado.
    ///
    /// A técnica é sobre-alocar e apontar para dentro. Não usa
    /// `alloc::alloc_zeroed` com `Layout::from_size_align` para não ter de
    /// gerir a desalocação à mão — o `Vec` faz isso, e o custo é uma
    /// sobre-alocação de menos de um bloco.
    pub fn novo(tamanho: usize, alinhamento: usize) -> Self {
        let alinhamento = alinhamento.max(1);
        let dados = vec![0u8; tamanho + alinhamento];
        let endereco = dados.as_ptr() as usize;
        let inicio = (alinhamento - (endereco % alinhamento)) % alinhamento;
        Self {
            dados,
            inicio,
            tamanho,
        }
    }

    pub fn como_fatia(&self) -> &[u8] {
        &self.dados[self.inicio..self.inicio + self.tamanho]
    }

    pub fn como_fatia_mut(&mut self) -> &mut [u8] {
        &mut self.dados[self.inicio..self.inicio + self.tamanho]
    }

    /// O endereço está mesmo alinhado?
    pub fn esta_alinhado(&self, alinhamento: usize) -> bool {
        alinhado(self.como_fatia().as_ptr() as u64, alinhamento)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn o_buffer_comeca_sempre_num_endereco_alinhado() {
        // `Vec<u8>` cai onde o alocador quiser; e o `O_DIRECT` recusa qualquer
        // endereco que nao esteja alinhado. Este e o teste que impede o mesmo
        // erro que o `advise_slice` tinha com o `madvise`.
        for alinhamento in [512usize, 4096, 8192] {
            for tamanho in [1usize, 511, 4096, 100_000] {
                let b = BufferAlinhado::novo(tamanho, alinhamento);
                assert_eq!(b.como_fatia().len(), tamanho);
                assert!(
                    b.esta_alinhado(alinhamento),
                    "tamanho={tamanho} alinhamento={alinhamento}: endereco desalinhado"
                );
            }
        }
    }

    #[test]
    fn o_buffer_e_escrevivel_na_fatia_util() {
        let mut b = BufferAlinhado::novo(4096, 4096);
        b.como_fatia_mut().fill(0xAB);
        assert!(b.como_fatia().iter().all(|&x| x == 0xAB));
        assert_eq!(b.como_fatia().len(), 4096);
    }

    #[test]
    fn o_alinhamento_de_offset_e_tamanho_e_verificavel() {
        assert!(alinhado(0, 4096));
        assert!(alinhado(4096, 4096));
        assert!(alinhado(8192, 4096));
        assert!(!alinhado(1, 4096));
        assert!(!alinhado(4095, 4096));
        // Buffered nao tem alinhamento nenhum: tudo passa.
        assert!(alinhado(1, 1));
        assert!(alinhado(12345, 0));
    }

    #[test]
    fn abrir_bulk_nunca_falha_por_o_direct_nao_estar_disponivel() {
        // §19: "fallback seguro para buffered I/O". Uma exportacao para o
        // lakehouse nao pode falhar porque o sistema de ficheiros de destino
        // nao suporta uma optimizacao.
        let temp = tempfile::tempdir().unwrap();
        let caminho = temp.path().join("bulk.bin");
        std::fs::write(&caminho, vec![7u8; 8192]).unwrap();

        let aberto = abrir_bulk(&caminho).expect("abrir_bulk nunca deve falhar por O_DIRECT");
        assert!(aberto.file.metadata().unwrap().len() == 8192);
        // O modo depende da maquina; o que se exige e que seja DITO.
        match &aberto.modo {
            ModoBulk::Directo { alinhamento } => {
                assert!(alinhamento.is_power_of_two() && *alinhamento >= 512);
            }
            ModoBulk::Buffered { motivo } => {
                assert!(!motivo.is_empty(), "um fallback mudo é um fallback perdido");
            }
        }
    }

    #[test]
    fn buffered_reporta_alinhamento_1_para_o_chamador_nao_ter_de_ramificar() {
        let m = ModoBulk::Buffered {
            motivo: "teste".into(),
        };
        assert_eq!(m.alinhamento(), 1);
        assert!(!m.e_directo());
        assert!(alinhado(12_345, m.alinhamento()));
    }
}
