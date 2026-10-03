//! SPEC-0089 §14, passos 4–5 (conferência de 2026-10-02): a destruição de
//! chave tem UMA porta — `Engine::shred_effect`, que só corre dentro de um
//! `execute_admin` (intenção durável antes do efeito) e verifica que o token
//! foi emitido para esse titular.
//!
//! `KeyStore::shred` continua `pub` (vive noutro crate e o servidor precisa de
//! o chamar), portanto o compilador não impede uma segunda chamada directa num
//! handler novo. Este gate impede: qualquer chamada nova a `.shred(` sobre o
//! keystore fora do `shred_effect` falha aqui, e quem a escreve tem de
//! justificar a excepção em vez de contornar o protocolo em silêncio.

use std::path::Path;

fn fontes(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entrada in std::fs::read_dir(dir).unwrap() {
        let p = entrada.unwrap().path();
        if p.is_dir() {
            fontes(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn keystore_shred_so_e_chamado_pelo_shred_effect() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut ficheiros = Vec::new();
    fontes(&src, &mut ficheiros);
    let mut chamadas = Vec::new();
    for f in &ficheiros {
        let texto = std::fs::read_to_string(f).unwrap();
        for (n, linha) in texto.lines().enumerate() {
            let codigo = linha.split("//").next().unwrap_or("");
            // Chamadas ao KeyStore: `ks.shred(` / `keystore...shred(`. As
            // chamadas a `engine.shred(` / `self.shred(` passam pelo protocolo.
            if codigo.contains("ks.shred(")
                || (codigo.contains("keystore") && codigo.contains(".shred("))
            {
                chamadas.push(format!("{}:{}", f.display(), n + 1));
            }
        }
    }
    assert_eq!(
        chamadas.len(),
        1,
        "KeyStore::shred tem de ter UMA chamada (Engine::shred_effect); encontradas: {chamadas:#?}"
    );
    assert!(chamadas[0].contains("engine.rs"), "{chamadas:?}");
}
