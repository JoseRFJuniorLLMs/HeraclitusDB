use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Hybrid logical clock. Layout: physical millis << 16 | logical counter.
///
/// Guarantees strict monotonicity within a process even when the wall clock
/// stalls or steps backwards. Distributed merging (`observe`) takes the max.
///
/// Nota sobre o layout: o contador lógico ocupa os 16 bits baixos, por isso um
/// incremento a partir de um valor com o contador cheio TRANSBORDA para o campo
/// físico — o relógio passa a "inventar" milissegundos de parede. É inerente ao
/// esquema e inofensivo a ritmos reais (exigiria >65536 eventos no MESMO
/// milissegundo, ~65M/s, acima do que o log single-writer atinge). Ver
/// [`Hlc::observe`] para porque é que o adiantamento NÃO pode ser limitado, e
/// [`Hlc::skew_ms`] para a métrica que o torna observável.
#[derive(Debug, Default)]
pub struct Hlc {
    last: AtomicU64,
}

impl Hlc {
    pub fn new() -> Self {
        Self::default()
    }

    fn physical_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Produce the next timestamp, strictly greater than any previous one.
    pub fn now(&self) -> u64 {
        let phys = Self::physical_now() << 16;
        loop {
            let last = self.last.load(Ordering::SeqCst);
            // `saturating_add`: com o `last + 1` cru, um `last` em `u64::MAX`
            // entrava em panic (debug) ou dava WRAP para 0 (release). O wrap
            // quebra a monotonicidade estrita de ts por LSN — precisamente o
            // contrato de que `lsn_for_timestamp` (AS OF TIMESTAMP) depende,
            // porque faz busca binária sobre ts assumindo-os ordenados.
            let next = if phys > last {
                phys
            } else {
                last.saturating_add(1)
            };
            if self
                .last
                .compare_exchange(last, next, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return next;
            }
        }
    }

    /// Merge a timestamp observed from a remote peer (ou relido do disco no
    /// `Log::open`).
    ///
    /// **Deliberadamente sem tecto de skew.** Foi tentado limitar a adoção a
    /// `physical_now() + N ms` para um peer com o relógio partido não prender o
    /// HLC local no futuro. Está ERRADO, e o teste
    /// `heraclitus-log/tests/v2_compat.rs::hlc_never_starts_behind_persisted_timestamps`
    /// prova porquê: um carimbo JÁ PERSISTIDO é um facto do histórico. Se o
    /// relógio não o ultrapassar, o append seguinte recebe um ts MENOR num LSN
    /// MAIOR — e `lsn_for_timestamp` (AS OF TIMESTAMP) faz busca binária a
    /// assumir ts não-decrescente por LSN. Recusar a adoção não evita sequer o
    /// envenenamento: o registo é aplicado na mesma (uma entrada commitada por
    /// quórum TEM de ser aplicada), logo o `Log::open` seguinte adota-o de
    /// qualquer forma — só que já com a ordenação partida pelo meio.
    ///
    /// O modelo de faltas assumido é o do Raft: não-bizantino. Um líder que
    /// carimbe futuro absurdo está fora do modelo. Use [`Hlc::skew_ms`] como
    /// métrica para detetar essa condição em operação.
    pub fn observe(&self, remote: u64) {
        self.last.fetch_max(remote, Ordering::SeqCst);
    }

    /// Quantos ms o HLC está à frente do relógio de parede (0 se alinhado).
    /// Serve de métrica operacional: um valor a subir denuncia clock skew ou um
    /// peer a carimbar futuro.
    pub fn skew_ms(&self) -> u64 {
        (self.last.load(Ordering::SeqCst) >> 16).saturating_sub(Self::physical_now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic() {
        let hlc = Hlc::new();
        let mut prev = 0;
        for _ in 0..10_000 {
            let t = hlc.now();
            assert!(t > prev);
            prev = t;
        }
    }

    #[test]
    fn observe_advances() {
        let hlc = Hlc::new();
        let far_future = (Hlc::physical_now() + 1_000_000) << 16;
        hlc.observe(far_future);
        assert!(hlc.now() > far_future);
    }

    /// O `skew_ms` mede o adiantamento face ao relógio de parede — é a métrica
    /// que substitui o tecto de skew que NÃO se pode impor no `observe` (ver o
    /// doc-comment de `observe`: limitar a adoção parte a monotonicidade de ts
    /// por LSN de que o AS OF TIMESTAMP depende).
    #[test]
    fn skew_ms_denuncia_relogio_adiantado() {
        let hlc = Hlc::new();
        assert_eq!(hlc.skew_ms(), 0, "relógio fresco está alinhado");
        let adiantado = (Hlc::physical_now() + 30_000) << 16;
        hlc.observe(adiantado);
        let skew = hlc.skew_ms();
        assert!(
            (29_000..=31_000).contains(&skew),
            "skew reportado ({skew}) tem de aproximar os 30s injetados"
        );
    }

    /// REGRESSÃO: `u64::MAX` fazia `last + 1` entrar em panic (debug) ou dar
    /// wrap para 0 (release) — e o wrap quebra a monotonicidade estrita que o
    /// `lsn_for_timestamp` (AS OF TIMESTAMP) assume na busca binária.
    #[test]
    fn now_satura_em_vez_de_dar_wrap() {
        let hlc = Hlc::new();
        hlc.last.store(u64::MAX, Ordering::SeqCst);
        let t = hlc.now();
        assert_eq!(t, u64::MAX, "satura no topo");
        assert_ne!(t, 0, "nunca dá wrap para zero");
        assert!(hlc.now() >= t, "continua não-decrescente");
    }
}
