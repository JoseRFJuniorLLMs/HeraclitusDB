//! Utilitários compartilhados entre os módulos de datasets.

use encoding_rs::WINDOWS_1252;
use std::path::Path;

/// Lê um arquivo CSV em Windows-1252/Latin-1 e devolve o conteúdo como String UTF-8.
pub fn ler_csv_latin1(path: &Path) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let bytes = std::fs::read(path)?;
    let (texto, _, teve_erros) = WINDOWS_1252.decode(&bytes);
    if teve_erros {
        tracing::warn!(
            "    Alguns caracteres não decodificáveis em {}",
            path.display()
        );
    }
    Ok(texto.into_owned())
}

/// Sanitiza um valor de campo para uso seguro como attr.
pub fn sanitizar(s: &str) -> String {
    s.trim().replace(['\0', '\r'], "").to_string()
}

/// Normaliza um nome próprio para comparação (entity resolution).
///
/// - maiúsculas, sem acentos, só letras A-Z e espaço, espaços colapsados.
/// Ex.: "José Uélisson Alves Leite" → "JOSE UELISSON ALVES LEITE".
pub fn normalizar_nome(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut ultimo_espaco = true; // evita espaço inicial
    for c in s.chars() {
        let c = match c {
            'á' | 'à' | 'â' | 'ã' | 'ä' | 'Á' | 'À' | 'Â' | 'Ã' | 'Ä' => 'A',
            'é' | 'è' | 'ê' | 'ë' | 'É' | 'È' | 'Ê' | 'Ë' => 'E',
            'í' | 'ì' | 'î' | 'ï' | 'Í' | 'Ì' | 'Î' | 'Ï' => 'I',
            'ó' | 'ò' | 'ô' | 'õ' | 'ö' | 'Ó' | 'Ò' | 'Ô' | 'Õ' | 'Ö' => 'O',
            'ú' | 'ù' | 'û' | 'ü' | 'Ú' | 'Ù' | 'Û' | 'Ü' => 'U',
            'ç' | 'Ç' => 'C',
            'ñ' | 'Ñ' => 'N',
            outro => outro.to_ascii_uppercase(),
        };
        if c.is_ascii_alphabetic() {
            out.push(c);
            ultimo_espaco = false;
        } else if !ultimo_espaco {
            out.push(' ');
            ultimo_espaco = true;
        }
    }
    out.trim_end().to_string()
}

/// Extrai os dígitos VISÍVEIS de um CPF mascarado como chave de blocking.
///
/// O Portal mascara `ABC.DEF.GHI-JK` como `***.DEF.GHI-**`, expondo só os 6
/// dígitos do meio. Esta função devolve esses 6 dígitos (ex.: `***.293.227-**`
/// → `"293227"`). Strings sem exatamente 6 dígitos visíveis devolvem "" (não
/// servem como bloco confiável). **Nunca reconstrói o CPF — só usa o fragmento
/// público já divulgado como chave de agrupamento.**
pub fn cpf_fragmento(mascarado: &str) -> String {
    let digitos: String = mascarado.chars().filter(|c| c.is_ascii_digit()).collect();
    if digitos.len() == 6 {
        digitos
    } else {
        String::new()
    }
}

/// Similaridade entre dois nomes normalizados via Jaccard de conjuntos de tokens.
/// Ignora partículas ("DE","DA","DO","DOS","DAS","E"). Retorna [0.0, 1.0].
pub fn similaridade_nome(a_norm: &str, b_norm: &str) -> f64 {
    fn tokens(s: &str) -> std::collections::BTreeSet<&str> {
        s.split_whitespace()
            .filter(|t| !matches!(*t, "DE" | "DA" | "DO" | "DOS" | "DAS" | "E"))
            .collect()
    }
    let (ta, tb) = (tokens(a_norm), tokens(b_norm));
    if ta.is_empty() || tb.is_empty() {
        return 0.0;
    }
    let inter = ta.intersection(&tb).count() as f64;
    let uniao = ta.union(&tb).count() as f64;
    inter / uniao
}

/// Converte valor monetário brasileiro (ex: "1.234,56") para string limpa.
pub fn sanitizar_valor(s: &str) -> String {
    let s = s.trim();
    // Remove aspas, espaços, converte vírgula decimal
    s.replace(['"', '\r'], "").trim().to_string()
}

/// Quantos appends manter EM VOO ao mesmo tempo.
///
/// O `Append` do gRPC é unário — um evento por chamada
/// (`crates/heraclitus-proto/proto/heraclitus.proto:7`) — e o log usa
/// `FsyncPolicy::GroupCommit`. Um emissor serial (enviar → esperar ACK →
/// repetir) espera a sua própria janela de fsync a cada evento, por isso o
/// débito fica preso perto de `1000 / intervalo_ms` e **não melhora com
/// hardware melhor**. Medido nesta carga a 2026-08-19: **86 eventos/s**, ou
/// seja 28 horas para os 8,87 milhões de linhas de `D:\dados-governo`.
///
/// Com N appends em voo, o worker do log junta-os num só lote (até 128
/// comandos, `heraclitus-log/src/lib.rs:651`) e um único fsync amortiza-se por
/// todos. É a mesma mitigação que a auditoria de escrita mediu no motor puro
/// (3,1x a 20M registos, `docs/md/auditorias/otimizacao-20m.md` §2.2), aqui
/// aplicada ao lado do cliente.
///
/// Afinável por `HERACLITUS_INGEST_INFLIGHT`. O valor certo depende de onde
/// está o gargalo do servidor: se for LATÊNCIA (fsync, round-trip), o débito
/// sobe quase linearmente com este número; se for um LOCK global (as views são
/// indexadas sob um só mutex, `heraclitus-server/src/engine.rs:409`), satura e
/// subir mais só acrescenta espera. Medir antes de escolher.
///
/// A correção estrutural é um RPC `AppendBatch`, que exige mexer no servidor.
const INFLIGHT_PADRAO: usize = 16;

fn appends_em_voo() -> usize {
    static V: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        let n = std::env::var("HERACLITUS_INGEST_INFLIGHT")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(INFLIGHT_PADRAO);
        tracing::info!("  Appends em voo: {n}");
        n
    })
}

/// Um append com recuo exponencial em erros TRANSITÓRIOS.
///
/// # A ressalva que a carga de 2026-08-19 ensinou
///
/// Um `Timeout expired` do lado do cliente **não significa que o evento não
/// foi escrito.** Observado nessa carga: sob pressão de memória, a pool de
/// tarefas bloqueantes do servidor (um `spawn_blocking` por evento,
/// `heraclitus-server/src/grpc.rs:90`) saturou nas 512 threads, os pedidos
/// ficaram em fila, e o cliente desistiu — mas ao matar o cliente o `head` do
/// log **saltou 138 mil eventos**, porque a fila drenou e escreveu-os.
///
/// Ou seja: o resultado de um append que expira é **desconhecido**, não
/// negativo. Reenviá-lo pode DUPLICAR o evento. Num log append-only imutável,
/// duplicar é permanente.
///
/// A forma correta de o resolver já existe na API — `AppendRequest.
/// idempotency_key`, que faz o servidor devolver o LSN original num reenvio
/// byte-equivalente. Este ETL ainda não a usa (a chave estável teria de vir de
/// `dataset+ficheiro+linha`), e enquanto não usar, **o retry aqui troca
/// eventos em falta por eventos possivelmente duplicados**. Para uma carga de
/// dados abertos é o compromisso certo; para um ledger financeiro não seria.
///
/// Por isso o retry é curto (2 tentativas extra) e só cobre erros que são
/// claramente transitórios de transporte.
async fn enviar_com_retry(
    cli: &mut heraclitus_client::Client,
    agente: &str,
    content: &[u8],
    opts: heraclitus_client::AppendOptions,
) -> Result<u64, heraclitus_client::tonic::Status> {
    use heraclitus_client::AppendOptions;
    const TENTATIVAS: usize = 3;
    let mut espera = std::time::Duration::from_millis(200);
    let mut ultimo: Option<heraclitus_client::tonic::Status> = None;

    for tentativa in 0..TENTATIVAS {
        // `AppendOptions` não é `Clone`; reconstrói-se por tentativa.
        let o = AppendOptions {
            session_id: opts.session_id.clone(),
            kind: opts.kind.clone(),
            hyp: opts.hyp.clone(),
            attrs: opts.attrs.clone(),
            parents: opts.parents.clone(),
            idempotency_key: opts.idempotency_key.clone(),
        };
        match cli.append(agente, content, o).await {
            Ok(lsn) => return Ok(lsn),
            Err(e) => {
                let transitorio = matches!(
                    e.code(),
                    heraclitus_client::tonic::Code::Unavailable
                        | heraclitus_client::tonic::Code::DeadlineExceeded
                        | heraclitus_client::tonic::Code::Cancelled
                        | heraclitus_client::tonic::Code::ResourceExhausted
                );
                if !transitorio || tentativa + 1 == TENTATIVAS {
                    return Err(e);
                }
                ultimo = Some(e);
                tokio::time::sleep(espera).await;
                espera *= 3;
            }
        }
    }
    Err(ultimo.unwrap_or_else(|| heraclitus_client::tonic::Status::unknown("retry esgotado")))
}

/// Envia um lote de eventos para o HeraclitusDB via gRPC, com
/// [`appends_em_voo`] chamadas concorrentes. Retorna quantos foram aceites.
pub async fn enviar_lote(
    client: Option<&mut heraclitus_client::Client>,
    lote: &[(String, Vec<u8>, std::collections::HashMap<String, String>)],
    agent_id: &str,
) -> u64 {
    let Some(c) = client else {
        return lote.len() as u64; // dry-run
    };
    if lote.is_empty() {
        return 0;
    }

    // Reparte o lote por tarefas. `chunks` exige tamanho >= 1 mesmo quando o
    // lote é menor que a concorrência — daí o `max(1)`.
    let por_tarefa = lote.len().div_ceil(appends_em_voo()).max(1);
    let mut tarefas = tokio::task::JoinSet::new();

    for pedaco in lote.chunks(por_tarefa) {
        // `spawn` exige 'static: o cliente clona-se (partilha o mesmo canal
        // HTTP/2) e os itens copiam-se para dentro da tarefa.
        let mut cli = c.clone();
        let agente = agent_id.to_string();
        let itens = pedaco.to_vec();
        tarefas.spawn(async move {
            let mut ok = 0u64;
            let mut falhas = 0u64;
            for (kind, content, attrs) in itens {
                let opts = heraclitus_client::AppendOptions {
                    kind,
                    attrs,
                    ..Default::default()
                };
                match enviar_com_retry(&mut cli, &agente, &content, opts).await {
                    Ok(_lsn) => ok += 1,
                    Err(e) => {
                        // Só o primeiro erro de cada tarefa é registado: numa
                        // carga de milhões, um servidor em baixo produzia
                        // milhões de linhas de log iguais.
                        if falhas == 0 {
                            tracing::warn!("    gRPC append falhou apos retries: {e}");
                        }
                        falhas += 1;
                    }
                }
            }
            if falhas > 1 {
                tracing::warn!("    ... mais {} falhas nesta tarefa", falhas - 1);
            }
            ok
        });
    }

    let mut ok = 0u64;
    while let Some(r) = tarefas.join_next().await {
        match r {
            Ok(n) => ok += n,
            Err(e) => tracing::warn!("    tarefa de envio abortou: {e}"),
        }
    }
    ok
}
