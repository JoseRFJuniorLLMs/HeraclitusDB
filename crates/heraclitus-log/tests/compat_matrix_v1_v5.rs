//! SPEC-0050 §206 — "v1-v5 permanecem legíveis", como matriz e não como
//! afirmação.
//!
//! Antes deste ficheiro a compatibilidade estava coberta por `v2_compat.rs`,
//! que fabrica **um** segmento v2. Isso prova o v2 e nada mais: as gerações v1
//! (CRC/leaf só sobre o payload), v3 (`StoragePayloadV3`, sem valid time), v4
//! (valid time, CRC-32/ISO) e v5 (CRC-32C Castagnoli) nunca eram exercitadas
//! por um teste — e são precisamente onde as regras divergem.
//!
//! A matriz cobre, para **cada** versão 1..=5:
//!
//! | propriedade | porque importa |
//! |---|---|
//! | abrir + ler devolve os episódios intactos | é o mínimo de "legível" |
//! | os campos que a geração **não** persistia voltam a `None`/vazio | v1–v3 não têm valid time; inventá-lo seria falsificar o passado |
//! | a raiz Merkle da geração fecha sob a regra **dessa** geração | v1 hasheia o payload; v2+ a região autenticada |
//! | um flip no `lsn` do registo é detectado em v2+ e **não** em v1 | é a diferença que motivou o bump 1→2; se o teste não a vir, o decode versionado deixou de existir |
//! | escrever por cima continua a funcionar | reabrir dados antigos não pode exigir migração implícita |
//!
//! O último ponto é o que impede a regressão mais cara: um leitor que
//! silenciosamente aplicasse a regra do v5 a um segmento v1 leria lixo como
//! dados válidos, e a raiz selada mudaria sem que ninguém tivesse tocado no
//! ficheiro.

use heraclitus_core::config::FsyncPolicy;
use heraclitus_core::{Episode, EventKind};
use heraclitus_log::format::{self, Decoded};
use heraclitus_log::Log;
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Todas as gerações que esta build promete ler.
const VERSOES: [u16; 5] = [1, 2, 3, 4, 5];

fn episodios() -> Vec<Episode> {
    (0..4u64)
        .map(|i| {
            let mut e = Episode::new(
                "compat",
                if i % 2 == 0 {
                    EventKind::Observation
                } else {
                    EventKind::Custom(format!("Kind{i}"))
                },
                format!("conteudo-{i}").into_bytes(),
            );
            e.session_id = format!("sessao-{i}");
            e.attrs.insert("uf".into(), "SP".into());
            e.attrs.insert("n".into(), i.to_string());
            // Valid time só existe a partir do v4. Preenchê-lo aqui é
            // deliberado: as versões antigas TÊM de o perder, e o teste
            // verifica essa perda em vez de a contornar.
            e.valid_from = Some(1_000 + i);
            e.valid_to = Some(2_000 + i);
            e
        })
        .collect()
}

/// Escreve à mão um segmento na geração `version`, selado, e devolve as folhas
/// Merkle na ordem em que o leitor as recomputa.
fn escrever_segmento(dir: &Path, version: u16, eps: &[Episode]) -> Vec<[u8; 32]> {
    let path = dir.join(format!("{:020}.hrkl", 0));
    let mut f = File::create(&path).unwrap();
    f.write_all(
        &format::SegmentHeader {
            version,
            segment_id: 0,
            created_hlc: 1,
        }
        .encode(),
    )
    .unwrap();

    let mut folhas = Vec::new();
    for (i, e) in eps.iter().enumerate() {
        let payload =
            heraclitus_log::encode_storage_payload_for_version(version, e.id.0.to_bytes(), e)
                .unwrap();
        let rec = format::encode_record(version, i as u64, e.ts_hlc, &payload);
        folhas.push(format::record_leaf(version, &rec));
        f.write_all(&rec).unwrap();
    }
    f.write_all(
        &format::SegmentFooter {
            record_count: eps.len() as u64,
            min_lsn: 0,
            max_lsn: eps.len() as u64 - 1,
            blake3_root: heraclitus_log::merkle_root(&folhas),
        }
        .encode(),
    )
    .unwrap();
    f.sync_all().unwrap();
    folhas
}

/// O que a geração `version` conseguia persistir de um `Episode`.
fn esperado_para_versao(version: u16, original: &Episode) -> Episode {
    let mut e = original.clone();
    if version < 4 {
        // Valid time nasceu no v4: um segmento anterior não o tem, e o leitor
        // não pode inventá-lo.
        e.valid_from = None;
        e.valid_to = None;
    }
    e
}

#[test]
fn cada_versao_de_1_a_5_abre_le_e_preserva_o_que_persistia() {
    let eps = episodios();
    for v in VERSOES {
        let dir = tempfile::tempdir().unwrap();
        escrever_segmento(dir.path(), v, &eps);

        let log = Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        let lidos = log.scan(0, eps.len() as u64).unwrap();
        assert_eq!(lidos.len(), eps.len(), "v{v}: contagem de registos");

        for (i, (lsn, lido)) in lidos.iter().enumerate() {
            let esperado = esperado_para_versao(v, &eps[i]);
            assert_eq!(*lsn, i as u64, "v{v}: LSN");
            assert_eq!(lido.id, esperado.id, "v{v}: EventId");
            assert_eq!(lido.agent_id, esperado.agent_id, "v{v}: agent_id");
            assert_eq!(lido.session_id, esperado.session_id, "v{v}: session_id");
            assert_eq!(lido.kind, esperado.kind, "v{v}: kind");
            assert_eq!(lido.content, esperado.content, "v{v}: content");
            assert_eq!(lido.attrs, esperado.attrs, "v{v}: attrs");
            assert_eq!(lido.parents, esperado.parents, "v{v}: parents");
            assert_eq!(
                lido.valid_from, esperado.valid_from,
                "v{v}: valid_from — uma geração pré-v4 não pode devolver valid time"
            );
            assert_eq!(lido.valid_to, esperado.valid_to, "v{v}: valid_to");
        }
    }
}

#[test]
fn cada_versao_verifica_a_sua_propria_raiz_merkle() {
    // A raiz selada tem de fechar sob a regra da geração que a escreveu. Se o
    // leitor aplicasse a regra do v5 a um segmento v1, isto falharia — que é
    // exactamente o ponto.
    let eps = episodios();
    for v in VERSOES {
        let dir = tempfile::tempdir().unwrap();
        escrever_segmento(dir.path(), v, &eps);
        let log = Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        let r = log.verify().unwrap();
        assert_eq!(
            r.merkle_ok, r.sealed,
            "v{v}: {} de {} segmentos selados fecharam a raiz",
            r.merkle_ok, r.sealed
        );
        assert_eq!(r.sealed, 1, "v{v}: o segmento fabricado devia estar selado");
        assert_eq!(r.records as usize, eps.len(), "v{v}: registos varridos");
    }
}

#[test]
fn folha_e_crc_do_v1_cobrem_so_o_payload_e_do_v2_mais_a_regiao_autenticada() {
    // A diferença que motivou o bump 1→2, verificada nos dois sentidos. Um
    // leitor que perdesse o despacho por versão passaria num dos lados e
    // falharia no outro.
    let e = &episodios()[0];
    let payload = heraclitus_log::encode_storage_payload_for_version(1, e.id.0.to_bytes(), e)
        .unwrap();

    for (v, deve_detectar) in [(1u16, false), (2, true), (3, true), (4, true), (5, true)] {
        let bom = format::encode_record(v, 7, e.ts_hlc, &payload);
        assert!(
            matches!(format::decode_record(v, &bom), Decoded::Record(7, _, _, _)),
            "v{v}: o registo íntegro tinha de decodificar"
        );

        // Flip num bit do campo `lsn` — dentro da região autenticada do v2+,
        // fora da do v1.
        let mut mau = bom.clone();
        mau[8] ^= 0x01;
        let detectou = matches!(format::decode_record(v, &mau), Decoded::Torn);
        assert_eq!(
            detectou, deve_detectar,
            "v{v}: deteção de flip no lsn devia ser {deve_detectar}"
        );

        // A folha Merkle segue a mesma regra.
        let move_a_raiz = format::record_leaf(v, &bom) != format::record_leaf(v, &mau);
        assert_eq!(
            move_a_raiz, deve_detectar,
            "v{v}: um flip no lsn devia mover a raiz? {deve_detectar}"
        );
    }
}

#[test]
fn v5_e_v4_diferem_no_crc_e_nao_no_payload() {
    // O bump 4→5 trocou CRC-32/ISO por CRC-32C. Se algum dia alguém "unificar"
    // os dois caminhos, um segmento v4 passa a falhar o CRC e o log antigo
    // torna-se ilegível — a regressão mais cara possível.
    let e = &episodios()[0];
    let p4 = heraclitus_log::encode_storage_payload_for_version(4, e.id.0.to_bytes(), e).unwrap();
    let p5 = heraclitus_log::encode_storage_payload_for_version(5, e.id.0.to_bytes(), e).unwrap();
    assert_eq!(p4, p5, "v4 e v5 partilham o layout do payload");

    let r4 = format::encode_record(4, 0, e.ts_hlc, &p4);
    let r5 = format::encode_record(5, 0, e.ts_hlc, &p5);
    assert_ne!(&r4[4..8], &r5[4..8], "o campo CRC tem de diferir");
    assert_eq!(&r4[8..], &r5[8..], "tudo o resto é idêntico");

    // Ler um com a regra do outro é `Torn`, nunca um registo aceite.
    assert!(matches!(format::decode_record(5, &r4), Decoded::Torn));
    assert!(matches!(format::decode_record(4, &r5), Decoded::Torn));

    // Mas a folha Merkle é a mesma: o bump não mexeu na identidade.
    assert_eq!(format::record_leaf(4, &r4), format::record_leaf(5, &r5));
}

#[test]
fn reabrir_uma_geracao_antiga_continua_a_aceitar_escritas() {
    // §206 não exige só "legível": exige que reabrir dados antigos não force
    // uma migração. O log sela a cauda antiga e continua num segmento novo na
    // versão corrente, sem tocar nos bytes que já lá estavam.
    let eps = episodios();
    for v in VERSOES {
        let dir = tempfile::tempdir().unwrap();
        escrever_segmento(dir.path(), v, &eps);
        let antes = std::fs::read(dir.path().join(format!("{:020}.hrkl", 0))).unwrap();

        let log = Log::open(dir.path(), 1 << 20, FsyncPolicy::Always).unwrap();
        let lsn = log
            .append(Episode::new("novo", EventKind::Action, b"depois".to_vec()))
            .unwrap();
        assert_eq!(lsn, eps.len() as u64, "v{v}: o LSN novo continua a sequência");

        let (_l, lido) = log.read(lsn).unwrap().unwrap();
        assert_eq!(lido.content, b"depois", "v{v}: o registo novo relê-se");

        // Os antigos continuam lá e continuam certos.
        let todos = log.scan(0, eps.len() as u64 + 1).unwrap();
        assert_eq!(todos.len(), eps.len() + 1, "v{v}: total após append");

        // E os bytes do segmento antigo não foram reescritos.
        let depois = std::fs::read(dir.path().join(format!("{:020}.hrkl", 0))).unwrap();
        assert_eq!(
            antes, depois,
            "v{v}: o segmento antigo foi modificado ao reabrir"
        );
    }
}

#[test]
fn versao_futura_e_rejeitada_em_vez_de_interpretada() {
    // SPEC-029: um major mais novo que esta build é rejeição dura. Interpretar
    // bytes que o binário não entende é pior que recusar.
    let dir = tempfile::tempdir().unwrap();
    let eps = episodios();
    escrever_segmento(dir.path(), format::FORMAT_VERSION, &eps);

    // Reescreve só o byte da versão para FORMAT_VERSION + 1.
    let p = dir.path().join(format!("{:020}.hrkl", 0));
    let mut bytes = std::fs::read(&p).unwrap();
    bytes[4..6].copy_from_slice(&(format::FORMAT_VERSION + 1).to_le_bytes());
    std::fs::write(&p, &bytes).unwrap();

    let erro = Log::open(dir.path(), 1 << 20, FsyncPolicy::Always);
    assert!(
        erro.is_err(),
        "uma geração futura foi aceite em vez de rejeitada"
    );
}

#[test]
fn o_codificador_por_versao_bate_com_o_descodificador_por_versao() {
    // Se `encode_storage_payload_for_version` e `decode_episode_payload`
    // divergirem, toda a matriz acima passa a provar a sua própria cópia do
    // formato em vez do formato real.
    let eps = episodios();
    for v in VERSOES {
        for e in &eps {
            let payload =
                heraclitus_log::encode_storage_payload_for_version(v, e.id.0.to_bytes(), e)
                    .unwrap();
            let lido = heraclitus_log::decode_episode_payload(v, &payload).unwrap();
            let esperado = esperado_para_versao(v, e);
            assert_eq!(lido.id, esperado.id, "v{v}");
            assert_eq!(lido.content, esperado.content, "v{v}");
            assert_eq!(lido.attrs, esperado.attrs, "v{v}");
            assert_eq!(lido.valid_from, esperado.valid_from, "v{v}");
            assert_eq!(lido.valid_to, esperado.valid_to, "v{v}");
        }
    }
}

#[test]
fn versao_desconhecida_no_codificador_e_erro_claro() {
    let e = &episodios()[0];
    for v in [0u16, format::FORMAT_VERSION + 1, u16::MAX] {
        assert!(
            heraclitus_log::encode_storage_payload_for_version(v, [0; 16], e).is_err(),
            "v{v} devia ser recusada"
        );
    }
}
