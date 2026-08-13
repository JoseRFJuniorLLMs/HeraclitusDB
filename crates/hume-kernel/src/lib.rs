//! HUME kernel — primitivas de hardware da plataforma de execução (SPEC-0040.1 §4).
//!
//! Este crate é a **fundação física** do motor HUME descrito em `SPEC-000`,
//! `SPEC-0038`, `SPEC-0040` e `SPEC-0041`. Contém apenas as primitivas de mais
//! baixo nível, sem qualquer dependência externa (`std`-only):
//!
//! - [`memory::AlignedBuffer`] — buffer contíguo alinhado a linha de cache
//!   (64 bytes), pronto para SIMD, com libertação O(1) (`SPEC-0041 §4`,
//!   `memory/aligned_alloc.rs`).
//! - [`selection::SelectionVector`] — vetor de seleção **adaptativo** que
//!   comuta entre `Bitmap` (alta densidade, ops booleanas bit a bit) e
//!   `Index16`/`Index32` (baixa densidade, materialização tardia rápida),
//!   conforme a seletividade real medida em runtime (`SPEC-0041 §1-2`,
//!   `selection/bitmap.rs`).
//!
//! ## Honestidade de escopo
//!
//! Estas são as peças da **ordem normativa** `SPEC-0040.1 §7` (itens 2 e 4) e a
//! base do item 1 (DataChunk ABI). São **módulos de referência reais e
//! testados** — não estão ligados ao caminho de query vivo (que continua no
//! DataFusion/Arrow, invariante I4). A distinção "módulo ✅ vs wired" segue a
//! disciplina de `docs/md/SPEC-new/STATUS.md`.

pub mod arena;
pub mod chunk;
pub mod compression;
pub mod memory;
pub mod morsel;
pub mod selection;
pub mod validity;
pub mod vector;

pub use arena::ScratchAllocator;
pub use chunk::{DataChunk, Device, PhysicalRowId};
pub use memory::AlignedBuffer;
pub use morsel::{MorselSizer, PipelineProfiler, MORSEL_LADDER};
pub use selection::SelectionVector;
pub use validity::ValidityMask;
pub use vector::{DataType, Vector};

/// Alinhamento canónico (linha de cache) para todos os buffers do HUME.
///
/// Escolhido para casar com a largura de registo AVX-512 (64 B) e a linha de
/// cache dominante em x86_64/ARM64 modernos, eliminando *split loads*.
pub const CACHE_LINE: usize = 64;
