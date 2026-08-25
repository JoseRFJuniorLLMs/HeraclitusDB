//! SPEC-0050 §209 — exportador Delta Lake.
//!
//! ## Porque o Delta é o exportador fácil
//!
//! O log de transacções do Delta é **JSON por linha** em
//! `_delta_log/<versão de 20 dígitos>.json`; cada linha é uma acção
//! (`protocol`, `metaData`, `add`, `remove`). Não há Avro, não há binário, não
//! há esquema externo. O que existe é uma regra de nomes rígida e uma
//! sequência de versões que não pode ter buracos.
//!
//! ## §209: "Delta utiliza Parquet derivado"
//!
//! Este módulo **nunca** materializa linhas. Recebe os
//! [`super::ExportedFile`] que o [`super::parquet_export`] produziu e escreve
//! metadados que apontam para esses mesmos caminhos. É o que garante que uma
//! contagem por Delta e uma contagem por Iceberg não podem divergir: leem os
//! mesmos ficheiros.
//!
//! ## O que não está aqui
//!
//! Deletion vectors, change data feed, column mapping, checkpoints Parquet.
//! Uma tabela append-only sem partições não precisa de nenhum deles, e cada um
//! que se acrescentasse "por precaução" seria código não exercitado a
//! descrever um estado que nunca ocorre.
//!
//! Um leitor Delta reconstrói o estado lendo todas as versões do log; sem
//! checkpoint isso é O(n) no número de commits, o que para uma tabela que
//! ganha um commit por segmento demotado é irrelevante durante muito tempo. Se
//! deixar de ser, o checkpoint é o passo seguinte — e é aditivo.

use std::collections::BTreeMap;

use heraclitus_core::HeraclitusError;
use serde::{Deserialize, Serialize};

use super::{ExportedFile, ExportProvenance};

/// Versões do protocolo. `(1, 2)` é o par mínimo que cobre `metaData` com
/// `configuration` — subir sem necessidade excluiria leitores antigos por
/// nada.
pub const MIN_READER_VERSION: u32 = 1;
pub const MIN_WRITER_VERSION: u32 = 2;

/// Caminho da entrada do log para uma versão.
///
/// 20 dígitos com zeros à esquerda: é o que faz a ordenação lexicográfica
/// coincidir com a ordenação numérica, que é como um leitor Delta lista o
/// directório.
pub fn log_path(version: u64) -> String {
    format!("_delta_log/{version:020}.json")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Protocol {
    #[serde(rename = "minReaderVersion")]
    pub min_reader_version: u32,
    #[serde(rename = "minWriterVersion")]
    pub min_writer_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Format {
    pub provider: String,
    #[serde(default)]
    pub options: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetaData {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub format: Format,
    /// O esquema em JSON do Delta (string, não objecto — é assim no protocolo).
    #[serde(rename = "schemaString")]
    pub schema_string: String,
    #[serde(rename = "partitionColumns")]
    pub partition_columns: Vec<String>,
    #[serde(default)]
    pub configuration: BTreeMap<String, String>,
    #[serde(rename = "createdTime", skip_serializing_if = "Option::is_none")]
    pub created_time: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Add {
    pub path: String,
    #[serde(rename = "partitionValues")]
    pub partition_values: BTreeMap<String, String>,
    pub size: u64,
    #[serde(rename = "modificationTime")]
    pub modification_time: i64,
    #[serde(rename = "dataChange")]
    pub data_change: bool,
    /// Estatísticas em JSON — o `numRecords` é o que um leitor usa para contar
    /// sem abrir os ficheiros.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<String>,
    /// Proveniência do Heraclitus. O Delta preserva tags desconhecidas, e é
    /// aqui que a linhagem sobrevive à travessia para o lakehouse.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Remove {
    pub path: String,
    #[serde(rename = "deletionTimestamp", skip_serializing_if = "Option::is_none")]
    pub deletion_timestamp: Option<i64>,
    #[serde(rename = "dataChange")]
    pub data_change: bool,
}

/// Uma acção do log. `untagged` não serve aqui: o Delta identifica a acção pela
/// **chave do objecto**, e é isso que este enum reproduz.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Action {
    #[serde(rename = "protocol")]
    Protocol(Protocol),
    #[serde(rename = "metaData")]
    MetaData(Box<MetaData>),
    #[serde(rename = "add")]
    Add(Box<Add>),
    #[serde(rename = "remove")]
    Remove(Remove),
}

/// Um commit: a versão e as suas acções, já em JSONL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaCommit {
    pub version: u64,
    pub path: String,
    pub bytes: Vec<u8>,
    pub actions: Vec<Action>,
}

/// O esquema Delta correspondente ao Parquet exportado.
///
/// Escrito à mão em vez de derivado do `arrow_schema` de propósito: o Delta
/// tem o seu próprio vocabulário de tipos, e uma conversão automática
/// esconderia a decisão de que `binary` do Arrow vira `binary` do Delta e não
/// `string`.
pub fn schema_string() -> String {
    fn campo(nome: &str, tipo: &str, nulavel: bool) -> serde_json::Value {
        serde_json::json!({
            "name": nome,
            "type": tipo,
            "nullable": nulavel,
            "metadata": {}
        })
    }
    serde_json::json!({
        "type": "struct",
        "fields": [
            campo("lsn", "long", false),
            campo("id", "string", false),
            campo("agent_id", "string", false),
            campo("session_id", "string", false),
            campo("ts_hlc", "long", false),
            campo("kind", "string", false),
            campo("content", "binary", false),
            campo("attrs_json", "string", false),
            campo("parents_json", "string", false),
            campo("valid_from", "long", true),
            campo("valid_to", "long", true),
            campo("embedding_json", "string", true),
            campo("segment_id", "long", false),
            campo("generation", "long", false),
        ]
    })
    .to_string()
}

fn tags(prov: &ExportProvenance) -> BTreeMap<String, String> {
    prov.key_values().into_iter().collect()
}

/// O commit 0: `protocol` + `metaData`.
///
/// `table_id` é fornecido pelo chamador (tipicamente o
/// `storage_namespace_id`), nunca gerado aqui: um UUID aleatório tornaria a
/// exportação não-determinística, e reexportar criaria uma tabela "diferente"
/// com os mesmos dados.
pub fn commit_inicial(
    table_id: &str,
    nome: Option<&str>,
    created_time: i64,
) -> Result<DeltaCommit, HeraclitusError> {
    let actions = vec![
        Action::Protocol(Protocol {
            min_reader_version: MIN_READER_VERSION,
            min_writer_version: MIN_WRITER_VERSION,
        }),
        Action::MetaData(Box::new(MetaData {
            id: table_id.to_string(),
            name: nome.map(|s| s.to_string()),
            description: Some(
                "Projecção analítica do log Heraclitus (SPEC-0050 §209). \
                 A verdade canónica é o HRKL; esta tabela é derivada e re-gerável."
                    .into(),
            ),
            format: Format {
                provider: "parquet".into(),
                options: BTreeMap::new(),
            },
            schema_string: schema_string(),
            partition_columns: Vec::new(),
            configuration: BTreeMap::from([(
                "heraclitus.export_format_version".to_string(),
                super::EXPORT_FORMAT_VERSION.to_string(),
            )]),
            created_time: Some(created_time),
        })),
    ];
    render(0, actions)
}

/// Um commit que adiciona os ficheiros de uma exportação — e remove as
/// gerações que elas substituem.
///
/// O par `add`+`remove` na mesma versão é o que torna um repack visível para o
/// leitor sem nunca haver um instante em que as linhas apareçam duas vezes.
pub fn commit_append(
    version: u64,
    novos: &[ExportedFile],
    substituidos: &[String],
    modification_time: i64,
) -> Result<DeltaCommit, HeraclitusError> {
    if version == 0 {
        return Err(HeraclitusError::Config(
            "a versão 0 do log Delta é reservada ao protocol+metaData".into(),
        ));
    }
    let mut actions = Vec::with_capacity(novos.len() + substituidos.len());
    for caminho in substituidos {
        actions.push(Action::Remove(Remove {
            path: caminho.clone(),
            deletion_timestamp: Some(modification_time),
            // `dataChange: false`: as linhas não mudaram, só a sua
            // representação física. Um leitor de CDF não deve ver isto como
            // uma alteração de dados.
            data_change: false,
        }));
    }
    for f in novos {
        actions.push(Action::Add(Box::new(Add {
            path: f.path.clone(),
            partition_values: BTreeMap::new(),
            size: f.size(),
            modification_time,
            data_change: true,
            stats: Some(
                serde_json::json!({
                    "numRecords": f.rows,
                    "minValues": { "lsn": f.provenance.first_lsn },
                    "maxValues": { "lsn": f.provenance.last_lsn },
                    "nullCount": {}
                })
                .to_string(),
            ),
            tags: Some(tags(&f.provenance)),
        })));
    }
    render(version, actions)
}

fn render(version: u64, actions: Vec<Action>) -> Result<DeltaCommit, HeraclitusError> {
    let mut bytes = Vec::new();
    for a in &actions {
        let linha = serde_json::to_vec(a)
            .map_err(|e| HeraclitusError::Serialization(e.to_string()))?;
        bytes.extend_from_slice(&linha);
        bytes.push(b'\n');
    }
    Ok(DeltaCommit {
        version,
        path: log_path(version),
        bytes,
        actions,
    })
}

/// Relê um commit. Existe para os testes e para um `doctor` conseguir dizer o
/// que a tabela declara sem um engine Delta.
pub fn parse_commit(bytes: &[u8]) -> Result<Vec<Action>, HeraclitusError> {
    let mut out = Vec::new();
    for linha in bytes.split(|b| *b == b'\n') {
        if linha.is_empty() {
            continue;
        }
        out.push(
            serde_json::from_slice(linha)
                .map_err(|e| HeraclitusError::Serialization(e.to_string()))?,
        );
    }
    Ok(out)
}

/// Os caminhos Parquet que a tabela contém depois de aplicar todos os commits.
///
/// Reproduz a regra do Delta: `add` põe, `remove` tira, por ordem de versão.
/// É o que um teste usa para provar que um repack não deixou o ficheiro antigo
/// e o novo visíveis ao mesmo tempo.
pub fn estado_dos_ficheiros(commits: &[DeltaCommit]) -> Vec<String> {
    let mut vivos: BTreeMap<String, ()> = BTreeMap::new();
    let mut ordenados: Vec<&DeltaCommit> = commits.iter().collect();
    ordenados.sort_by_key(|c| c.version);
    for c in ordenados {
        for a in &c.actions {
            match a {
                Action::Add(add) => {
                    vivos.insert(add.path.clone(), ());
                }
                Action::Remove(r) => {
                    vivos.remove(&r.path);
                }
                _ => {}
            }
        }
    }
    vivos.into_keys().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prov(seg: u64, gen: u32, lo: u64, hi: u64) -> ExportProvenance {
        ExportProvenance::new([1; 16], seg, gen, [2; 32], [3; 32], 1, lo, hi, hi - lo + 1)
    }

    fn ficheiro(seg: u64, gen: u32, lo: u64, hi: u64) -> ExportedFile {
        let p = prov(seg, gen, lo, hi);
        ExportedFile {
            path: super::super::parquet_export::data_path(seg, gen),
            bytes: vec![0u8; 128],
            rows: hi - lo + 1,
            provenance: p,
        }
    }

    #[test]
    fn o_caminho_do_log_ordena_lexicograficamente() {
        assert_eq!(log_path(0), "_delta_log/00000000000000000000.json");
        assert_eq!(log_path(11), "_delta_log/00000000000000000011.json");
        // A propriedade que interessa: ordenar como texto == ordenar como número.
        let mut v: Vec<String> = (0..12u64).map(log_path).collect();
        let esperado = v.clone();
        v.sort();
        assert_eq!(v, esperado);
    }

    #[test]
    fn o_commit_zero_traz_protocol_e_metadata() {
        let c = commit_inicial("tabela-1", Some("eventos"), 1_700_000_000_000).unwrap();
        assert_eq!(c.version, 0);
        let lidas = parse_commit(&c.bytes).unwrap();
        assert_eq!(lidas.len(), 2);
        assert!(matches!(lidas[0], Action::Protocol(_)));
        match &lidas[1] {
            Action::MetaData(m) => {
                assert_eq!(m.id, "tabela-1");
                assert!(m.partition_columns.is_empty());
                // O esquema tem de conter o LSN — §209, "export preserva LSN".
                assert!(m.schema_string.contains("\"lsn\""));
            }
            outra => panic!("esperava metaData, veio {outra:?}"),
        }
    }

    #[test]
    fn o_commit_e_deterministico() {
        let a = commit_inicial("t", Some("e"), 7).unwrap();
        let b = commit_inicial("t", Some("e"), 7).unwrap();
        assert_eq!(a.bytes, b.bytes);
    }

    #[test]
    fn o_add_aponta_para_o_parquet_derivado_e_carrega_a_proveniencia() {
        // §209: "Delta utiliza Parquet derivado". O caminho no `add` TEM de ser
        // exactamente o do ficheiro exportado — não uma segunda materialização.
        let f = ficheiro(88, 1, 100, 199);
        let c = commit_append(1, std::slice::from_ref(&f), &[], 5).unwrap();
        match &parse_commit(&c.bytes).unwrap()[0] {
            Action::Add(add) => {
                assert_eq!(add.path, f.path);
                assert_eq!(add.size, f.size());
                let t = add.tags.as_ref().unwrap();
                assert_eq!(t.get("heraclitus.segment_id").unwrap(), "88");
                assert_eq!(t.get("heraclitus.generation").unwrap(), "1");
                assert!(t.contains_key("heraclitus.logical_root"));
                let stats: serde_json::Value =
                    serde_json::from_str(add.stats.as_ref().unwrap()).unwrap();
                assert_eq!(stats["numRecords"], 100);
                assert_eq!(stats["minValues"]["lsn"], 100);
                assert_eq!(stats["maxValues"]["lsn"], 199);
            }
            outra => panic!("esperava add, veio {outra:?}"),
        }
    }

    #[test]
    fn um_repack_nunca_deixa_as_duas_geracoes_visiveis() {
        // A propriedade que o par add+remove no MESMO commit existe para dar.
        let g1 = ficheiro(88, 1, 0, 99);
        let g2 = ficheiro(88, 2, 0, 99);
        let c0 = commit_inicial("t", None, 1).unwrap();
        let c1 = commit_append(1, std::slice::from_ref(&g1), &[], 2).unwrap();
        let c2 = commit_append(
            2,
            std::slice::from_ref(&g2),
            std::slice::from_ref(&g1.path),
            3,
        )
        .unwrap();

        assert_eq!(estado_dos_ficheiros(&[c0.clone(), c1.clone()]), vec![g1.path.clone()]);
        let final_ = estado_dos_ficheiros(&[c0, c1, c2]);
        assert_eq!(final_, vec![g2.path.clone()]);
        assert!(
            !final_.contains(&g1.path),
            "a geração substituída continuou visível — as linhas contariam a dobrar"
        );
    }

    #[test]
    fn remover_nao_e_uma_alteracao_de_dados() {
        // Um repack muda bytes, não factos. Marcar `dataChange: true` faria um
        // consumidor de change-data-feed reprocessar o histórico inteiro.
        let g1 = ficheiro(88, 1, 0, 99);
        let c = commit_append(1, &[], std::slice::from_ref(&g1.path), 9).unwrap();
        match &parse_commit(&c.bytes).unwrap()[0] {
            Action::Remove(r) => assert!(!r.data_change),
            outra => panic!("esperava remove, veio {outra:?}"),
        }
    }

    #[test]
    fn a_versao_zero_e_reservada() {
        assert!(commit_append(0, &[], &[], 1).is_err());
    }

    #[test]
    fn as_accoes_fazem_round_trip_pelo_json() {
        let f = ficheiro(1, 0, 0, 9);
        let c = commit_append(3, &[f], &["data/velho.parquet".into()], 11).unwrap();
        assert_eq!(parse_commit(&c.bytes).unwrap(), c.actions);
        // Uma acção por linha, sem linha vazia final a mais.
        assert_eq!(c.bytes.iter().filter(|b| **b == b'\n').count(), 2);
    }
}
