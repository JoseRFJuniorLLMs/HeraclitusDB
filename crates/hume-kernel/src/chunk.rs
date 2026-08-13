//! `DataChunk` — a ABI de dados do HUME (SPEC-0041 §1, SPEC-0038 §2).
//!
//! É a **unidade fundamental** que trafega entre todos os operadores físicos —
//! relacionais, de grafo, vetoriais ou de streaming. Junta as colunas
//! ([`Vector`]), o [`SelectionVector`] (linhas ativas, materialização tardia) e
//! os [`PhysicalRowId`] (endereços físicos persistentes para o *late fetch*).
//!
//! ## Honestidade de escopo
//!
//! Esta é a **struct de referência** que a ordem normativa `SPEC-0040.1 §7`
//! (item 1) especifica — o *contrato* de dados, montado sobre as primitivas
//! reais deste crate. NÃO está ligada ao caminho de query vivo (que usa Arrow
//! `RecordBatch` via DataFusion — invariante I4). O operador `LateFetch` que
//! resolveria os [`PhysicalRowId`] contra um column-store paginado **não
//! existe** (a auditoria classificou-o `INVIÁVEL_ESCALA` para este workload):
//! [`PhysicalRowId`] está aqui como a forma da ABI, não como mecanismo ativo.

use crate::selection::SelectionVector;
use crate::vector::Vector;

/// Onde reside o chunk (`SPEC-0041 §1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Device {
    Cpu,
    Gpu,
}

/// Endereço físico persistente de uma linha, para materialização tardia
/// (`SPEC-0041 §1`). Forma de ABI — sem operador de resolução ativo (ver módulo).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalRowId {
    pub segment_id: u32,
    pub page_id: u32,
    pub offset: u16,
}

/// Bloco colunar vetorizado: colunas + vetor de seleção + IDs físicos.
#[derive(Debug)]
pub struct DataChunk {
    columns: Vec<Vector>,
    selection: SelectionVector,
    row_ids: Vec<PhysicalRowId>,
    device: Device,
}

impl DataChunk {
    /// Monta um chunk a partir das colunas. Todas as colunas têm de ter o mesmo
    /// comprimento (o domínio do morsel); a seleção inicial é "tudo ativo".
    ///
    /// # Panics
    /// Se as colunas tiverem comprimentos diferentes.
    pub fn new(columns: Vec<Vector>) -> Self {
        let len = columns.first().map(|c| c.len()).unwrap_or(0);
        for c in &columns {
            assert_eq!(c.len(), len, "todas as colunas do DataChunk têm o mesmo comprimento");
        }
        Self {
            columns,
            selection: SelectionVector::all(len),
            row_ids: Vec::new(),
            device: Device::Cpu,
        }
    }

    /// Chunk vazio (0 colunas, 0 linhas).
    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    /// Número de colunas.
    #[inline]
    pub fn num_columns(&self) -> usize {
        self.columns.len()
    }

    /// Teto físico: linhas alocadas por coluna (o domínio).
    #[inline]
    pub fn capacity(&self) -> usize {
        self.selection.len()
    }

    /// Linhas vivas: quantas sobrevivem ao vetor de seleção atual.
    #[inline]
    pub fn cardinality(&self) -> usize {
        self.selection.selected()
    }

    /// Acede à coluna `i`.
    pub fn column(&self, i: usize) -> &Vector {
        &self.columns[i]
    }

    /// O vetor de seleção atual (linhas ativas).
    #[inline]
    pub fn selection(&self) -> &SelectionVector {
        &self.selection
    }

    /// Refina a seleção interseptando com `mask` (o resultado de um filtro).
    /// É assim que a filtragem se propaga sem materializar linhas.
    ///
    /// # Panics
    /// Se `mask` for de um domínio diferente.
    pub fn refine(&mut self, mask: &SelectionVector) {
        self.selection = self.selection.and(mask);
    }

    /// Anexa os IDs físicos das linhas (para *late fetch* futuro).
    pub fn set_row_ids(&mut self, ids: Vec<PhysicalRowId>) {
        self.row_ids = ids;
    }

    /// IDs físicos das linhas.
    #[inline]
    pub fn row_ids(&self) -> &[PhysicalRowId] {
        &self.row_ids
    }

    #[inline]
    pub fn device(&self) -> Device {
        self.device
    }

    /// Define o dispositivo (CPU/GPU) onde o chunk reside.
    pub fn with_device(mut self, device: Device) -> Self {
        self.device = device;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vector::Vector;

    fn sample() -> DataChunk {
        let score = Vector::from_i32(&(0..1000).collect::<Vec<i32>>());
        let ts = Vector::from_u64(&(0..1000).map(|x| x as u64).collect::<Vec<u64>>());
        DataChunk::new(vec![score, ts])
    }

    #[test]
    fn assembles_columns() {
        let c = sample();
        assert_eq!(c.num_columns(), 2);
        assert_eq!(c.capacity(), 1000);
        assert_eq!(c.cardinality(), 1000); // tudo ativo por omissão
        assert_eq!(c.device(), Device::Cpu);
    }

    #[test]
    fn refine_narrows_cardinality() {
        let mut c = sample();
        // simula um filtro score > 900 → 99 sobreviventes (901..=999)
        let survivors: Vec<u32> = (901..1000).collect();
        let mask = SelectionVector::from_indices(1000, &survivors);
        c.refine(&mask);
        assert_eq!(c.cardinality(), 99);
        assert_eq!(c.capacity(), 1000); // domínio físico intocado
        assert_eq!(c.selection().to_indices(), survivors);
    }

    #[test]
    fn refine_is_composable() {
        let mut c = sample();
        c.refine(&SelectionVector::from_indices(1000, &(0..500).collect::<Vec<_>>()));
        c.refine(&SelectionVector::from_indices(1000, &(400..600).collect::<Vec<_>>()));
        // interseção [0,500) ∩ [400,600) = [400,500) = 100 linhas
        assert_eq!(c.cardinality(), 100);
    }

    #[test]
    #[should_panic(expected = "mesmo comprimento")]
    fn rejects_ragged_columns() {
        let a = Vector::from_i32(&[1, 2, 3]);
        let b = Vector::from_i32(&[1, 2]);
        let _ = DataChunk::new(vec![a, b]);
    }

    #[test]
    fn row_ids_and_device() {
        let c = sample().with_device(Device::Gpu);
        assert_eq!(c.device(), Device::Gpu);
        let mut c = c;
        c.set_row_ids(vec![PhysicalRowId { segment_id: 1, page_id: 2, offset: 3 }]);
        assert_eq!(c.row_ids().len(), 1);
        assert_eq!(c.row_ids()[0].offset, 3);
    }
}
