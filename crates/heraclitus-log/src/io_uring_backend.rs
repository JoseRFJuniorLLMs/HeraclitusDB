//! SPEC-0073 §8/§9 — o backend `io_uring`, experimental.
//!
//! ## A regra que governa este ficheiro inteiro
//!
//! A §9 fixa a ordem e proíbe o atalho:
//!
//! ```text
//! write submitted -> write completed -> durability barrier completed
//!   -> committed/durable LSN publicado -> client ACK
//!
//! É proibido:  submit fsync -> ACK -> completion chega depois
//! ```
//!
//! O io_uring existe precisamente para separar submeter de completar, e é essa
//! separação que torna o atalho fácil de escrever por acidente. Aqui ele é
//! impossível **por construção**: [`LinuxUringIo::append_batch`] e
//! [`LinuxUringIo::sync`] só regressam depois de a completion respectiva ter
//! sido colhida da CQ e o seu resultado verificado. Não há caminho no código
//! que devolva `Ok(())` com uma operação ainda em voo.
//!
//! É por isso que este backend, tal como está, **não é mais rápido** que o
//! `PortableFileIo` num append isolado: paga uma submissão e uma colheita onde
//! o outro paga uma syscall. O ganho do io_uring vem de submeter vários
//! pedidos antes de colher — e essa é a parte que a §10 manda medir e a §11
//! manda provar antes de promover. Implementar o batching agora, sem a matriz
//! de benchmark, seria escolher a forma da API a partir de teoria.
//!
//! ## O que não está aqui, por ordem da §8
//!
//! ```text
//! Não implementar inicialmente: SQPOLL, IOPOLL, busy polling agressivo
//! ```
//!
//! Nenhum dos três está. Ficam atrás do benchmark adicional que a §8 exige.

use crate::io_backend::LogIoBackend;
use std::fs::File;
use std::io;

/// Profundidade da submission queue.
///
/// 32 é folgado para o uso actual (uma operação de cada vez) e é o tecto para
/// quando o batching da §10 entrar. Uma fila maior custa memória fixa no kernel
/// sem servir para nada enquanto não houver várias submissões em voo.
const QUEUE_DEPTH: u32 = 32;

/// O backend `io_uring`.
///
/// Só existe em Linux e só quando a feature `linux-io-uring` está ligada. O
/// default continua a ser o `PortableFileIo`, como a §7 manda.
pub struct LinuxUringIo {
    file: File,
    ring: io_uring::IoUring,
    /// Offset da próxima escrita. O `io_uring` escreve por OFFSET explícito e
    /// não pelo cursor do ficheiro — não há um "append" implícito como no
    /// `write(2)` sequencial — portanto o offset é mantido aqui e avançado
    /// apenas quando a completion confirma quantos bytes entraram.
    offset: u64,
}

impl LinuxUringIo {
    /// Abre o anel sobre um ficheiro já aberto.
    ///
    /// `offset_inicial` é o tamanho actual do ficheiro: a primeira escrita
    /// continua de onde o segmento estava, e é responsabilidade de quem abre
    /// passá-lo certo. Um offset errado aqui escreveria por cima de registos
    /// selados, portanto vem do chamador que já o conhece em vez de ser
    /// adivinhado com um `seek`.
    pub fn novo(file: File, offset_inicial: u64) -> io::Result<Self> {
        let ring = io_uring::IoUring::new(QUEUE_DEPTH)?;
        Ok(Self {
            file,
            ring,
            offset: offset_inicial,
        })
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Submete uma entrada e **espera** pela sua completion.
    ///
    /// O `submit_and_wait(1)` é o que torna a §9 verdadeira: regressa só quando
    /// há pelo menos uma completion na CQ. O resultado é lido antes de esta
    /// função devolver, e um resultado negativo vira `io::Error` — nunca um
    /// `Ok(())` com o erro por colher.
    ///
    /// # Safety
    ///
    /// Quem chama garante que os buffers referidos pela entrada continuam
    /// válidos e imóveis até a completion ser colhida. Como esta função espera
    /// pela completion antes de regressar, isso reduz-se a "o buffer vive
    /// durante a chamada", que os chamadores dentro deste ficheiro cumprem por
    /// terem o buffer emprestado no seu próprio frame.
    unsafe fn submeter_e_esperar(&mut self, entrada: &io_uring::squeue::Entry) -> io::Result<i32> {
        // SAFETY: contrato acima; o chamador mantém os buffers vivos.
        unsafe {
            self.ring.submission().push(entrada).map_err(|_| {
                io::Error::other(
                    "submission queue cheia: a profundidade não chega para as operações em voo",
                )
            })?;
        }
        self.ring.submit_and_wait(1)?;
        let cqe = self
            .ring
            .completion()
            .next()
            .ok_or_else(|| io::Error::other("submit_and_wait(1) regressou sem completion"))?;
        let resultado = cqe.result();
        if resultado < 0 {
            return Err(io::Error::from_raw_os_error(-resultado));
        }
        Ok(resultado)
    }
}

impl LogIoBackend for LinuxUringIo {
    /// Escreve o lote inteiro, esperando pela completion de cada `write`.
    ///
    /// O ciclo existe porque o `write` do kernel pode escrever MENOS do que o
    /// pedido, exactamente como o `write(2)` — o `write_all` do `std` esconde
    /// isso e aqui é preciso fazê-lo à mão. Uma escrita curta que não fosse
    /// repetida deixaria o segmento com um registo truncado e o offset a mentir.
    fn append_batch(&mut self, bytes: &[u8]) -> io::Result<()> {
        use io_uring::{opcode, types};
        let mut escrito = 0usize;
        while escrito < bytes.len() {
            let fatia = &bytes[escrito..];
            let entrada = opcode::Write::new(
                types::Fd(std::os::fd::AsRawFd::as_raw_fd(&self.file)),
                fatia.as_ptr(),
                fatia.len() as u32,
            )
            .offset(self.offset + escrito as u64)
            .build();
            // SAFETY: `fatia` empresta `bytes`, que vive durante toda esta
            // chamada, e `submeter_e_esperar` colhe a completion antes de
            // regressar.
            let n = unsafe { self.submeter_e_esperar(&entrada)? };
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "io_uring escreveu 0 bytes",
                ));
            }
            escrito += n as usize;
        }
        self.offset += escrito as u64;
        Ok(())
    }

    /// A barreira de durabilidade.
    ///
    /// `fsync` com `FSYNC_DATASYNC` — o equivalente ao `fdatasync(2)`, que é o
    /// que o `PortableFileIo::sync` faz com `sync_data`. Os dois backends têm de
    /// prometer a MESMA coisa, senão o benchmark da §10 estaria a comparar
    /// durabilidades diferentes e o resultado não significaria nada.
    ///
    /// Espera pela completion. É aqui que a §9 se cumpre ou se quebra.
    fn sync(&mut self) -> io::Result<()> {
        use io_uring::{opcode, types};
        let entrada = opcode::Fsync::new(types::Fd(std::os::fd::AsRawFd::as_raw_fd(&self.file)))
            .flags(types::FsyncFlags::DATASYNC)
            .build();
        // SAFETY: o `Fsync` não referencia buffers do utilizador.
        unsafe { self.submeter_e_esperar(&entrada)? };
        Ok(())
    }

    /// Trunca, e sincroniza o offset interno com o novo tamanho.
    ///
    /// Sem o segundo passo, um rollback deixaria o `offset` a apontar para além
    /// do fim do ficheiro e a escrita seguinte abriria um buraco de zeros — o
    /// mesmo tipo de defeito que o `truncate.intent` do v5 tinha, e que custou
    /// um commit próprio a corrigir.
    fn truncar(&mut self, bytes: u64) -> io::Result<()> {
        self.file.set_len(bytes)?;
        self.offset = bytes;
        Ok(())
    }

    fn ficheiro(&mut self) -> &mut File {
        &mut self.file
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek};

    fn ficheiro() -> (tempfile::TempDir, File) {
        let dir = tempfile::tempdir().unwrap();
        let f = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(dir.path().join("seg.hrkl"))
            .unwrap();
        (dir, f)
    }

    fn ler(f: &mut File) -> Vec<u8> {
        let mut v = Vec::new();
        f.seek(std::io::SeekFrom::Start(0)).unwrap();
        f.read_to_end(&mut v).unwrap();
        v
    }

    /// O teste que interessa: os dois backends produzem os MESMOS bytes.
    ///
    /// Se algum dia divergirem, divergiram no caminho de durabilidade, e a §11
    /// deixa de poder comparar os dois — estaria a medir coisas diferentes.
    #[test]
    fn o_uring_produz_os_mesmos_bytes_que_o_portatil() {
        let registos: Vec<Vec<u8>> = (0..48u8).map(|i| vec![i; 1 + (i as usize % 61)]).collect();

        let (_d1, f1) = ficheiro();
        let mut uring = match LinuxUringIo::novo(f1, 0) {
            Ok(u) => u,
            // Um kernel sem io_uring (ou um container que o proíbe) não é uma
            // falha de teste: é o caso que o fallback existe para servir.
            Err(erro) => {
                eprintln!("io_uring indisponível nesta máquina ({erro}); teste saltado");
                return;
            }
        };
        for r in &registos {
            uring.append_batch(r).unwrap();
        }
        uring.sync().unwrap();

        let (_d2, f2) = ficheiro();
        let mut portatil = crate::io_backend::PortableFileIo::new(f2);
        for r in &registos {
            portatil.append_batch(r).unwrap();
        }
        portatil.sync().unwrap();

        assert_eq!(ler(uring.ficheiro()), ler(portatil.ficheiro()));
    }

    #[test]
    fn o_offset_acompanha_o_que_foi_escrito() {
        let (_d, f) = ficheiro();
        let Ok(mut uring) = LinuxUringIo::novo(f, 0) else {
            eprintln!("io_uring indisponível; teste saltado");
            return;
        };
        uring.append_batch(&[1u8; 100]).unwrap();
        assert_eq!(uring.offset(), 100);
        uring.append_batch(&[2u8; 50]).unwrap();
        assert_eq!(uring.offset(), 150);
        assert_eq!(uring.ficheiro().metadata().unwrap().len(), 150);
    }

    /// Truncar TEM de repor o offset.
    ///
    /// Sem isto a escrita seguinte abriria um buraco de zeros entre o novo fim
    /// e o offset velho — o mesmo defeito do `truncate.intent` do v5.
    #[test]
    fn truncar_repoe_o_offset_e_nao_deixa_buraco() {
        let (_d, f) = ficheiro();
        let Ok(mut uring) = LinuxUringIo::novo(f, 0) else {
            eprintln!("io_uring indisponível; teste saltado");
            return;
        };
        uring.append_batch(&[9u8; 200]).unwrap();
        uring.truncar(64).unwrap();
        assert_eq!(uring.offset(), 64);

        uring.append_batch(&[7u8; 8]).unwrap();
        let bytes = ler(uring.ficheiro());
        assert_eq!(bytes.len(), 72, "um buraco de zeros teria dado mais de 72");
        assert!(bytes[..64].iter().all(|&b| b == 9));
        assert!(bytes[64..].iter().all(|&b| b == 7));
    }

    #[test]
    fn continuar_de_um_offset_inicial_nao_escreve_por_cima() {
        let (_d, mut f) = ficheiro();
        // Simula um segmento com registos já selados.
        use std::io::Write;
        f.write_all(&[3u8; 40]).unwrap();
        f.sync_data().unwrap();

        let Ok(mut uring) = LinuxUringIo::novo(f, 40) else {
            eprintln!("io_uring indisponível; teste saltado");
            return;
        };
        uring.append_batch(&[4u8; 10]).unwrap();
        let bytes = ler(uring.ficheiro());
        assert_eq!(bytes.len(), 50);
        assert!(
            bytes[..40].iter().all(|&b| b == 3),
            "escreveu por cima de registos selados"
        );
        assert!(bytes[40..].iter().all(|&b| b == 4));
    }
}
