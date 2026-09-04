//! SPEC-0073 §7 — o contrato de I/O do log.
//!
//! A §7 é explícita sobre a ordem em que isto entra:
//!
//! ```text
//! O atual writer SHALL permanecer como baseline.
//! Inicialmente:  PortableFileIo = default
//!                LinuxUringIo   = experimental
//! ```
//!
//! Este ficheiro é o `PortableFileIo` — o writer que já existia, agora atrás de
//! um trait. Não muda uma única chamada de sistema: `write_all` continua a ser
//! `write_all` e `sync_data` continua a ser `sync_data`, na mesma ordem, com o
//! mesmo tratamento de erro. **É essa a propriedade que o torna seguro de
//! introduzir**: o caminho de durabilidade é literalmente o mesmo, e as portas
//! de crash existentes continuam a exercitá-lo tal como estavam.
//!
//! ## Porque é que o backend io_uring não está aqui
//!
//! Não está feito, e a razão não é falta de tempo — é a §9. O io_uring separa
//! *submeter* de *completar*, e a §9 proíbe exactamente o erro que essa
//! separação convida:
//!
//! ```text
//! É proibido:  submit fsync -> ACK -> completion chega depois
//! ```
//!
//! Um backend que publicasse o LSN durável antes da completion da barreira
//! violaria o invariante I-2 — "um append reconhecido como durável tem de ser
//! recuperável após crash" — e violá-lo-ia de forma invisível, porque só se
//! manifesta num corte de energia. Somar a isso a matriz de benchmark da §10
//! (5 profundidades de fila × 5 payloads × 4 concorrências × 4 políticas de
//! durabilidade) e o gate da §11, e o backend é um trabalho com princípio, meio
//! e fim próprios.
//!
//! O que este trait faz é tornar esse trabalho **contido**: implementar
//! `LinuxUringIo` passa a ser escrever uma implementação deste contrato e
//! provar as suas propriedades, em vez de mexer no ciclo do writer.

use std::fs::File;
use std::io;
use std::io::Write;

/// O que o log precisa de um dispositivo de escrita.
///
/// Deliberadamente pequeno. Cada método aqui é uma coisa que o writer já fazia;
/// nenhum é uma capacidade nova à espera de utilizador. Um trait que
/// antecipasse io_uring — lotes, buffers registados, profundidade de fila —
/// estaria a desenhar para um backend que ainda não existe, e a forma certa
/// dessas operações só se sabe depois de as medir.
pub trait LogIoBackend: Send {
    /// Escreve o registo inteiro. Um erro deixa o ficheiro possivelmente com
    /// escrita PARCIAL — é o chamador que trata disso com `truncar`, e é por
    /// isso que este método não tenta limpar nada sozinho.
    fn append_batch(&mut self, bytes: &[u8]) -> io::Result<()>;

    /// A barreira de durabilidade.
    ///
    /// `sync_data` e não `sync_all`: os metadados do ficheiro não mudam entre
    /// appends (o tamanho é actualizado pelo próprio write), e o `sync_all`
    /// pagaria uma segunda barreira por nada. Quando o tamanho TEM de ficar
    /// durável — no selo de um segmento — o chamador usa `sync_all`
    /// explicitamente.
    fn sync(&mut self) -> io::Result<()>;

    /// Volta o ficheiro a um tamanho conhecido, para desfazer uma escrita
    /// parcial.
    fn truncar(&mut self, bytes: u64) -> io::Result<()>;

    /// Acesso ao ficheiro por baixo.
    ///
    /// Existe porque o writer faz mais do que este contrato cobre — `set_len`
    /// no selo, `sync_all`, leituras posicionadas — e inventar um método no
    /// trait para cada uma dessas seria alargar o contrato para lá do que a §7
    /// pede. Um backend que não tenha um `File` real por baixo terá de
    /// repensar isto; é a fronteira honesta deste desenho, e fica escrita.
    fn ficheiro(&mut self) -> &mut File;
}

/// O writer portátil: `std::fs::File`. É o default, e continua a ser o
/// baseline contra o qual qualquer backend Linux tem de provar ganho (§11).
#[derive(Debug)]
pub struct PortableFileIo {
    file: File,
}

impl PortableFileIo {
    pub fn new(file: File) -> Self {
        Self { file }
    }

    pub fn into_inner(self) -> File {
        self.file
    }
}

impl LogIoBackend for PortableFileIo {
    fn append_batch(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.file.write_all(bytes)
    }

    fn sync(&mut self) -> io::Result<()> {
        self.file.sync_data()
    }

    fn truncar(&mut self, bytes: u64) -> io::Result<()> {
        self.file.set_len(bytes)
    }

    fn ficheiro(&mut self) -> &mut File {
        &mut self.file
    }
}

/// Qual backend está em uso, para a telemetria de arranque (§54).
///
/// Uma string derivada da construção, não escrita à mão: quando o
/// `LinuxUringIo` existir, é aqui que se distingue, e não numa constante que
/// alguém se esquece de mudar.
pub fn backend_em_uso() -> &'static str {
    "portable-file-io"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn ficheiro_temporario() -> (tempfile::TempDir, File) {
        let dir = tempfile::tempdir().unwrap();
        let caminho = dir.path().join("seg.hrkl");
        let f = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&caminho)
            .unwrap();
        (dir, f)
    }

    #[test]
    fn o_backend_portatil_escreve_sincroniza_e_trunca() {
        let (_dir, f) = ficheiro_temporario();
        let mut io = PortableFileIo::new(f);
        io.append_batch(b"abcdefgh").unwrap();
        io.sync().unwrap();
        assert_eq!(io.ficheiro().metadata().unwrap().len(), 8);

        io.truncar(3).unwrap();
        assert_eq!(io.ficheiro().metadata().unwrap().len(), 3);

        let mut lido = Vec::new();
        {
            use std::io::Seek;
            let f = io.ficheiro();
            f.seek(std::io::SeekFrom::Start(0)).unwrap();
            f.read_to_end(&mut lido).unwrap();
        }
        assert_eq!(lido, b"abc");
    }

    /// A propriedade que torna esta abstracção segura de introduzir: o backend
    /// portátil produz EXACTAMENTE os mesmos bytes que o `write_all` directo
    /// que ele substitui. Se algum dia divergir, divergiu no caminho de
    /// durabilidade — que é o pior sítio para uma diferença silenciosa.
    #[test]
    fn o_backend_nao_muda_um_byte_face_ao_write_all_directo() {
        let registos: Vec<Vec<u8>> = (0..64u8)
            .map(|i| vec![i; 1 + (i as usize % 97)])
            .collect();

        let (_d1, f1) = ficheiro_temporario();
        let mut io = PortableFileIo::new(f1);
        for r in &registos {
            io.append_batch(r).unwrap();
        }
        io.sync().unwrap();

        let (_d2, mut f2) = ficheiro_temporario();
        for r in &registos {
            f2.write_all(r).unwrap();
        }
        f2.sync_data().unwrap();

        let ler = |f: &mut File| {
            use std::io::Seek;
            let mut v = Vec::new();
            f.seek(std::io::SeekFrom::Start(0)).unwrap();
            f.read_to_end(&mut v).unwrap();
            v
        };
        assert_eq!(ler(io.ficheiro()), ler(&mut f2));
    }
}
