# SPEC-0093 — Document Ingestion & Structural Geometry Adapter

**Status:** Draft / Proposed  
**Data:** 01/10/2026  
**Classe:** Ingestion / PDF Extraction / Document Geometry / Security Normalization  
**Prioridade:** P1  
**Dependências:** SPEC-0092, SPEC-0045 (Sentinel), SPEC-0087 (Forensics)  
**Alvos:** novo crate `heraclitus-doc-adapter`, `heraclitus-sentinel`  
**Princípio:** *O firewall de injeção documental depende da fidelidade geométrica e estrutural da extração. Um parser ingênuo que extrai apenas fluxo corrido de texto é cego à esteganografia.*

---

## 0. Decisão e Escopo

A **SPEC-0092** estabeleceu o núcleo computacional e as regras determinísticas de detecção de injeção de prompt e coerção de ferramentas em documentos não confiáveis (`UNTRUSTED_DOCUMENT -> DATA_ONLY`). Esse núcleo é deliberadamente desacoplado de parsers concretos de arquivo.

Esta **SPEC-0093** define a arquitetura, contratos e requisitos de segurança do **Adaptador de Ingestão de Documentos**, encarregado de:

1. Consumir documentos reais (PDF 1.4–2.0, PDF/A, DOCX, ODT, HTML e imagens com OCR);
2. Preservar integralmente os bytes de origem para compromisso criptográfico (SHA-256 / BLAKE3);
3. Extrair a camada de texto associada às coordenadas físicas e atributos de renderização (bounding boxes, transformações afins, cores, opacidade, recorte e oclusão por imagens);
4. Mapear regiões semânticas do documento (cabeçalho, rodapé, anotações, campos de formulário, metadados XMP/InfoDict e corpo);
5. Normalizar spans estruturados para alimentar a API canônica de `DocumentFirewall::inspect`.

---

## 1. Modelo de Ameaça do Parser

O parser de documentos opera na borda hostil do sistema:

- **PDF Malformado / ZIP Bomb / DoS**: Arquivos desenhados para causar estouro de memória, recursão infinita, loops de descompressão ou exaustão de CPU.
- **Camadas Fantasma / Ocultação Tipográfica**:
  - Texto renderizado em modo `3` (Neither fill nor stroke — invisível);
  - Caracteres colocados sob operadores `Do` (imagens opacas) com z-index inferior;
  - Texto com matriz de transformação degenerada (`Tm` com escala próxima de zero);
  - Texto além dos limites de `MediaBox`, `CropBox` ou recortado por caminhos de clip (`W`/`W*`);
  - Cores idênticas ou delta-E inferior a limiares perceptivos humanos;
- **Manipulação de Unicode e BiDi**:
  - Injeção de sequências zero-width (`U+200B`, `U+FEFF`);
  - Inversão visual por controles bidirecionais (`U+202E`, `U+2066`..`U+2069`);
  - Desassociação entre `ToUnicode` CMaps e glifos reais renderizados;
- **Anotações e Metadados Ocultos**:
  - Comentários fora de página ou com opacidade zero;
  - Diretivas de prompt injection em metadados Dublin Core, XMP ou PDF Info Dictionary.

---

## 2. Contrato de Ingestão e Tipagem

O adaptador deve expor a trait:

~~~rust
pub trait DocumentIngestionAdapter: Send + Sync {
    /// Ingesta bytes brutos e gera a coleção de spans geométricos normalizados.
    fn extract_spans(
        &self,
        document_bytes: &[u8],
        options: &IngestionOptions,
    ) -> Result<DocumentExtractionResult, IngestionError>;
}

#[derive(Debug, Clone)]
pub struct IngestionOptions {
    pub max_pages: u32,
    pub max_spans_per_page: usize,
    pub memory_budget_bytes: usize,
    pub render_ocr_fallback: bool,
    pub extract_annotations: bool,
    pub extract_metadata: bool,
}

#[derive(Debug, Clone)]
pub struct DocumentExtractionResult {
    pub original_sha256: String,
    pub page_count: u32,
    pub spans: Vec<DocumentSpan>,
    pub metadata_spans: Vec<DocumentSpan>,
    pub parser_diagnostics: Vec<ParserDiagnostic>,
}
~~~

Cada `DocumentSpan` mapeia diretamente para o tipo de `heraclitus-sentinel::document_security::DocumentSpan`.

---

## 3. Extração Geométrica e de Renderização

Para cada elemento textual do documento, o adaptador deve extrair:

| Atributo | Origem no PDF | Requisito de Extração |
|---|---|---|
| `bbox` | Text Matrix `Tm` + Font BBox + CTM | Coordenadas absolutas na página em pontos tipográficos `[x0, y0, x1, y1]` |
| `page_bbox` | `CropBox` (ou `MediaBox` na ausência) | Limites visíveis da página |
| `font_size_pt` | Parâmetro `Tfs` multiplicado pelo determinante de `Tm` | Tamanho efetivo renderizado |
| `foreground` | `rg` / `k` / `cs` / `sc` cor de preenchimento atual | Hexadecimal canônico `#RRGGBB` |
| `background` | Varredura do canvas inferior sob o `bbox` | Hexadecimal canônico `#RRGGBB` ou `#FFFFFF` por omissão |
| `opacity` | Graphic State Extended (`ca` / `CA`) | Valor float `[0.0, 1.0]` |
| `clipped` | Interseção com clipping path atual (`W` / `W*`) | Booleano: `true` se completamente fora da área de recorte |
| `behind_image` | Z-index versus operadores de imagem `Do` | Booleano: `true` se imagem opaca foi renderizada sobre a área |
| `transform_scale` | Determinante da matriz `Tm` × `CTM` | Detecção de escala micro-geométrica |
| `region` | Coordenadas Y versus margens de página | `Header` (topo 10%), `Footer` (base 10%), `Body`, `Annotation`, etc. |

---

## 4. Normalização Unicode e Canonicalização

1. **NFKC Estável**: Antes de alimentar o firewall, os identificadores são submetidos a decomposição de compatibilidade seguida de recomposição canônica.
2. **Preservação de Pistas**: Os caracteres de controle Unicode invisíveis (`U+200B`, `U+FEFF`, `U+202A`..`U+202E`, `U+2066`..`U+2069`) **não** devem ser eliminados na extração de `DocumentSpan::text`, pois são a evidência necessária para a regra `DOC-STEG-002`. Sua remoção ocorre exclusivamente na geração do `sanitized_text` pelo `DocumentFirewall`.
3. **CMap Verification**: Se o documento contém `ToUnicode` inconsistente com a tabela padrão de codificação de fontes, o adaptador deve emitir `ParserDiagnostic::InconsistentCMap` com severidade `HIGH`.

---

## 5. Orçamento e Isolamento de Recursos (Fail-Closed)

O parser de documentos opera sob restrições estritas de recursos:

~~~text
+-----------------------------------------------------------+
|                      Ingestion Host                       |
|                                                           |
|  [Bytes] ---> Memory Budget Gate (ex: máx 64 MB)          |
|                  |                                        |
|                  v                                        |
|  [Isolated Worker / Safe Rust Parser]                     |
|    - Max pages: 1.000                                     |
|    - Max spans: 200.000                                   |
|    - Timeout: 5.000 ms                                    |
|                  |                                        |
|                  +---> OK: DocumentExtractionResult       |
|                  |                                        |
|                  +---> Exceeded: IngestionError::Budget   |
|                          (Documento QUARANTINED de imediato)
+-----------------------------------------------------------+
~~~

Qualquer falha de parser, corrupção estrutural ou estouro de orçamento resulta em **quarentena imediata** (`DocumentVerdict::Quarantined`) sob a premissa de que a incapacidade de analisar integralmente a geometria do documento impede a validação da ausência de esteganografia.

---

## 6. Gates de Qualificação (SPEC-0049)

Para ser aceito em ambiente de produção governamental, o adaptador de ingestão deve passar pelos seguintes testes:

1. **Gate DIG-01 (Micro-fontes & Cores)**: Teste com PDFs contendo texto branco em fundo branco e fontes de 0.1pt; verificar que `DOC-STEG-001` é disparado.
2. **Gate DIG-02 (Oclusão Geométrica)**: Teste com texto coberto por JPEG/PNG opaco; verificar que `behind_image=true` e `DOC-GEOM-001` é disparado.
3. **Gate DIG-03 (Clipping & Off-Page)**: Teste com texto posicionado em coordenadas negativas ou fora de `CropBox`; verificar que `clipped=true` ou `outside_page=true`.
4. **Gate DIG-04 (Unicode BiDi & Zero-Width)**: Teste com carga de injeção fragmentada por zero-width spaces e controles de direção; verificar preservação dos bytes no span e disparo de `DOC-STEG-002`.
5. **Gate DIG-05 (Integridade Criptográfica)**: Provar que `original_sha256` corresponde exatamente aos bytes do arquivo em disco sem mutação de um único bit.
