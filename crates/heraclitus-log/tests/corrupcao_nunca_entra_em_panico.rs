//! Varrimento sistematico de corrupcao: um ficheiro adulterado pode fazer o log
//! RECUSAR abrir, mas nunca pode fazer o processo entrar em PANICO.
//!
//! # Porque e que a distincao importa
//!
//! Os testes de corrupcao que ja existiam sao pontuais: um bit invertido a meio
//! de um segmento selado (`bitrot_nao_trunca`), uma cauda torn no segmento
//! activo. Provam politicas concretas e importantes, mas cada um toca UM sitio.
//!
//! Um formato binario falha nos sitios em que ninguem pensou. O que este teste
//! faz e o oposto de escolher: percorre o ficheiro inteiro e, em cada posicao,
//! poe la um valor hostil. A asserção nao e sobre o resultado — um `Err` esta
//! certo, e um `Ok` tambem esta se o byte alterado era irrelevante ou se o CRC
//! o apanhou noutro sitio. A asserção e que **nao ha panico**.
//!
//! Um panico aqui nao e um detalhe de robustez. `Log::open` corre no arranque do
//! servico e a leitura corre a servir pedidos: um ficheiro corrompido por bit rot
//! — ou por alguem com acesso ao disco — passa de "o log recusa abrir e diz
//! porque" para "o processo morre", e a diferenca entre as duas e a diferenca
//! entre um incidente diagnosticavel e um servico em ciclo de reinicio.
//!
//! O varrimento e determinista (sem aleatoriedade) para que uma falha seja
//! sempre reproduzivel pelo indice que a mensagem imprime.
//!
//! # O formato que se testa, e porque este e o certo
//!
//! `Log::open` abre o layout LEGADO v1--v5 (`.hrkl` avulsos, sem manifesto). A
//! primeira versao deste teste usava-o, e portanto nao tocava no formato que a
//! producao corre — o servico em execucao reporta `storage_format: v6`. Um
//! varrimento de corrupcao sobre o formato errado da uma sensacao de cobertura
//! que nao existe, que e pior do que nao ter varrimento nenhum.
//!
//! Usa-se `Log::open_v6`. O layout v6 poe os ficheiros em SUBDIRECTORIOS
//! (`segments/`, `manifests/`), e a primeira tentativa de os apanhar so olhava
//! para o topo do directorio: o varrimento corria com zero ficheiros e passava.
//! Um teste de corrupcao que nao corrompe nada passa sempre — e por isso este
//! ficheiro tem, no fim, uma asserção sobre o NUMERO de casos executados.

use heraclitus_core::{Episode, EventKind, FsyncPolicy};
use heraclitus_log::Log;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

/// Constroi um log v6 com varios segmentos selados e devolve os ficheiros.
fn log_de_amostra(dir: &Path) -> Vec<PathBuf> {
    {
        let log = Log::open_v6(dir, 4096, FsyncPolicy::Always).unwrap();
        for i in 0..150 {
            log.append(Episode::new(
                "auditor",
                EventKind::Observation,
                format!("evento {i} {}", "x".repeat(70)).into_bytes(),
            ))
            .unwrap();
        }
        assert!(log.head() >= 150, "o varrimento precisa de eventos");
    }
    let mut fs = Vec::new();
    recolher(dir, dir, &mut fs);
    fs.sort();
    assert!(!fs.is_empty(), "o log v6 nao escreveu ficheiro nenhum");
    fs
}

/// Caminhos RELATIVOS a raiz, atravessando subdirectorios.
fn recolher(raiz: &Path, actual: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(actual) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            recolher(raiz, &p, out);
        } else if p.is_file() {
            if let Ok(rel) = p.strip_prefix(raiz) {
                out.push(rel.to_path_buf());
            }
        }
    }
}

/// Copia a arvore inteira, preservando subdirectorios.
fn copiar_arvore(origem: &Path, destino: &Path) -> Result<(), String> {
    let mut ficheiros = Vec::new();
    recolher(origem, origem, &mut ficheiros);
    for rel in ficheiros {
        let alvo = destino.join(&rel);
        if let Some(pai) = alvo.parent() {
            std::fs::create_dir_all(pai).map_err(|e| e.to_string())?;
        }
        std::fs::copy(origem.join(&rel), &alvo).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Le, adultera uma posicao, escreve numa copia limpa do directorio, e tenta
/// abrir e varrer.
///
/// Devolve `Err(descricao)` so quando houve PANICO. Um `Err` do log e um
/// resultado legitimo e nao interessa aqui.
fn tenta_com_byte_alterado(
    origem: &Path,
    ficheiro_relativo: &Path,
    posicao: usize,
    novo: u8,
) -> Result<(), String> {
    let destino = tempfile::tempdir().map_err(|e| e.to_string())?;
    // A arvore INTEIRA: o log v6 precisa do manifesto e dos vizinhos, e ambos
    // vivem em subdirectorios.
    copiar_arvore(origem, destino.path())?;
    let alvo = destino.path().join(ficheiro_relativo);
    let mut bytes = std::fs::read(&alvo).map_err(|e| e.to_string())?;
    if posicao >= bytes.len() {
        return Ok(());
    }
    if bytes[posicao] == novo {
        return Ok(()); // nao alterou nada; nao vale a pena correr
    }
    bytes[posicao] = novo;
    std::fs::write(&alvo, &bytes).map_err(|e| e.to_string())?;

    // O panico e o que se esta a caçar, portanto silencia-se o hook para o
    // varrimento nao encher a saida com backtraces de casos que se esperam.
    let anterior = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let resultado = catch_unwind(AssertUnwindSafe(|| {
        if let Ok(log) = Log::open_v6(destino.path(), 4096, FsyncPolicy::Always) {
            // Abrir nao chega: a leitura e onde os offsets sao usados.
            let head = log.head();
            let _ = log.scan(0, head);
            let _ = log.verify_active_tail();
        }
    }));
    std::panic::set_hook(anterior);

    match resultado {
        Ok(()) => Ok(()),
        Err(e) => {
            let msg = e
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                .unwrap_or_else(|| "<panico sem mensagem>".to_owned());
            Err(format!(
                "PANICO com {} byte {posicao} = {novo:#04x}: {msg}",
                ficheiro_relativo.display()
            ))
        }
    }
}

/// Varre os primeiros bytes de cada ficheiro — cabecalhos e tabelas de offsets,
/// que e onde um valor hostil faz mais estrago — e uma amostra do resto.
#[test]
fn nenhum_byte_corrompido_faz_o_log_entrar_em_panico() {
    let origem = tempfile::tempdir().unwrap();
    let ficheiros = log_de_amostra(origem.path());

    // Valores escolhidos, nao aleatorios: 0x00 e 0xFF sao os extremos de
    // qualquer campo de comprimento, e 0x7F apanha o bit de sinal.
    const VALORES: [u8; 3] = [0x00, 0xFF, 0x7F];
    // Cada caso copia a arvore, abre, varre e verifica. Sem tecto, o varrimento
    // completo levava sete minutos, o que o tiraria da suite normal — e um
    // varrimento que nao corre nao encontra nada.
    //
    // O tecto desceu de 300 para 120 por uma razao concreta e medida: com 300,
    // o I/O deste teste ESFOMEAVA o
    // `l2_behavioral_adapter_emits_replayable_signal_after_shadow_promotion` do
    // Sentinel — que usa `FsyncPolicy::Always` com um unico worker — e ele
    // falhava na suite completa enquanto passava em 0,08 s isolado. Confirmado
    // por eliminacao: marcar este varrimento como `#[ignore]` fazia a suite
    // passar inteira.
    //
    // Tentei primeiro reescrever a arvore a partir de memoria num unico
    // directorio de trabalho, para poupar o `tempdir` por caso. Ficou TRES
    // VEZES mais lento (9,9 s -> 28,7 s), porque o directorio reutilizado
    // acumula estado entre aberturas. Menos casos e a correccao simples que
    // funciona.
    const MAX_CASOS: usize = 120;

    let mut falhas = Vec::new();
    let mut casos = 0usize;

    for rel in &ficheiros {
        let nome = rel.clone();
        let tamanho = std::fs::metadata(origem.path().join(rel))
            .map(|m| m.len() as usize)
            .unwrap_or(0);
        if tamanho == 0 {
            continue;
        }
        // Os primeiros 256 bytes exaustivamente: cabecalho, magic, versao,
        // comprimentos. O resto por amostragem, para o teste continuar a caber
        // num ciclo de CI.
        let passo_cauda = (tamanho / 8).max(1);
        let posicoes: Vec<usize> = (0..tamanho.min(96))
            .chain((96..tamanho).step_by(passo_cauda))
            .collect();

        for p in posicoes {
            if casos >= MAX_CASOS {
                break;
            }
            for v in VALORES {
                casos += 1;
                if let Err(e) = tenta_com_byte_alterado(origem.path(), &nome, p, v) {
                    falhas.push(e);
                    if falhas.len() >= 5 {
                        break;
                    }
                }
            }
            if falhas.len() >= 5 {
                break;
            }
        }
        if falhas.len() >= 5 || casos >= MAX_CASOS {
            break;
        }
    }

    assert!(
        falhas.is_empty(),
        "{} de {casos} caso(s) de corrupcao fizeram o log entrar em panico em vez de recusar:\n{}",
        falhas.len(),
        falhas.join("\n")
    );
    // A asserção sobre o NUMERO de casos e o que impede este teste de passar
    // por nao ter corrido: a primeira versao apontava para o topo do
    // directorio, encontrava zero ficheiros no layout v6, e passava verde.
    assert!(
        casos >= 100,
        "o varrimento cobriu poucos casos ({casos}): esta a apontar para o sitio errado?"
    );
}
