# SPEC-0094 — Forensic Document Evidence & Causal Visualizer

**Status:** Draft / Proposed  
**Data:** 01/10/2026  
**Classe:** Digital Forensics / Explainability / Causal Audit / UI Contract  
**Prioridade:** P1  
**Dependências:** SPEC-0092, SPEC-0087, SPEC-0076, SPEC-0085  
**Alvos:** `heraclitus-forensic`, `heraclitus-sentinel`, `heraclitus-server`  
**Princípio:** *Um bloqueio de segurança em ambiente judicial ou governamental não pode ser uma caixa-preta opaca. O auditor e o perito precisam ver exatamente onde o ataque estava oculto no documento e comprovar que nenhum efeito privilegiado vazou.*

---

## 0. Decisão Arquitetural

A **SPEC-0092** implementou o núcleo do firewall com modelo diferencial e eventos canônicos (`document.*`). A **SPEC-0087** define a cadeia de custódia e o pacote de evidência forense.

Esta **SPEC-0094** estabelece:

1. O contrato de exportação do **Pacote Forense de Segurança Documental** (integrado ao `EvidencePackage` da SPEC-0087);
2. O **Grafo Causal Verificável**: do byte do arquivo à decisão de política e comprovação de efeito zero;
3. O **Contrato de Visualização Pericial** para interfaces de auditoria governamentais e consolas de segurança (SOC/Agent Evidence Console);
4. O verificador offline independente para comprovação pericial em juízo ou auditoria externa.

---

## 1. Pacote Forense Documental (`DocumentEvidenceBundle`)

O artefato pericial exportado é estruturado em conformidade com o padrão da SPEC-0087:

~~~text
EvidencePackage/
├── manifest.json
├── manifest.sha256
├── evidence/
│   ├── source-document.pdf              <-- Bytes originais intactos
│   ├── human-view.txt                   <-- Texto visível a humanos
│   ├── machine-view.txt                 <-- Texto bruto extraído pelo parser
│   ├── normalized-view.txt              <-- Texto sem caracteres invisíveis
│   ├── hidden-view.txt                  <-- Conteúdo esteganográfico/oculto
│   └── sanitized-reader-payload.txt     <-- Payload DATA_ONLY fornecido à IA
├── analysis/
│   ├── document-findings.json           <-- Achados DOC-*, severidades, bboxes
│   ├── layer-hashes.json                <-- 6 digests SHA-256 e BLAKE3
│   └── causal-graph.json                <-- Trajetória determinística de decisão
├── proofs/
│   ├── sentinel-events.jsonl            <-- Eventos document.* derivados
│   ├── merkle-inclusion.json            <-- Prova de inclusão no HRKL
│   └── timestamp.tsr                    <-- Carimbo de tempo RFC 3161
└── report/
    └── forensic-audit-report.pdf        <-- Relatório visual consolidado
~~~

---

## 2. Invariante dos 6 Hashes Criptográficos

Para todo documento inspecionado, o manifesto pericial vincula deterministicamente 6 estados de representação:

~~~rust
pub struct DocumentLayerHashes {
    /// SHA-256 do arquivo original recebido na borda
    pub original_sha256: String,
    /// SHA-256 da projeção legível por humanos
    pub human_sha256: String,
    /// SHA-256 do texto bruto extraído pela máquina
    pub machine_sha256: String,
    /// SHA-256 da versão normalizada
    pub normalized_sha256: String,
    /// SHA-256 do delta invisível/esteganográfico
    pub hidden_sha256: String,
    /// SHA-256 da carga higienizada entregue ao leitor
    pub sanitized_sha256: String,
}
~~~

A evidência forense comprova a relação:

$$\text{Original} \xrightarrow{\text{Parser}} \{\text{Human}, \text{Machine}\} \xrightarrow{\Delta} \text{Hidden} \xrightarrow{\text{Firewall}} \text{Sanitized}$$

---

## 3. O Grafo Causal Verificável

O perito deve conseguir reconstituir a trajetória causal completa sem ambiguidade:

~~~text
[Documento Ingerido: SHA-256: e8f2...b1]
      │
      ├── Spans Geométricos Extraídos
      │      ├── Span #12: BBox [40, 780, 550, 795] | Header | Cor: #FFFFFF/#FFFFFF
      │      └── Span #45: BBox [-50, -20, -10, -5] | Off-Page | Opacity: 0.00
      │
      ├── Regras Violadas
      │      ├── DOC-STEG-001 (Micro-fonte / Visual Concealment) -> Finding DOCF-0001
      │      ├── DOC-HDR-001  (Diretiva em Header)              -> Finding DOCF-0002
      │      └── DOC-TOOL-001 (Tentativa de Coerção de Tool)    -> Finding DOCF-0003
      │
      ├── Veredicto do Firewall
      │      ├── DocumentVerdict::Quarantined
      │      ├── llm_exposure_allowed: false
      │      └── ReaderPayload: authority=DATA_ONLY, tools_allowed=false
      │
      ├── Registro no Log Imutável
      │      ├── Evento: document.prompt_injection.detected (LSN: 104859)
      │      ├── Evento: document.quarantined (LSN: 104860)
      │      └── Raiz Merkle: 0x9a3c...7f
      │
      └── Barreira do Agent Policy Gateway
             ├── Tentativa de invocação de ferramenta: NEGADA (Fail-Closed)
             └── Side-Effect no sistema: ZERO (delta_upstream = 0)
~~~

Essa cadeia prova tecnicamente que, mesmo que o agente de leitura tente obedecer ao texto do documento, o gateway central barrou a execução com zero efeitos colaterais.

---

## 4. Contrato de Visualização da Interface Pericial

Qualquer interface forense (como demonstrado na POC de referência `JoseRFJuniorLLMs/STF`) deve implementar os 5 modos de visualização obrigatórios:

1. **Visão Humana (`Human View`)**:
   Renderização idêntica à que um operador de triagem, advogado ou magistrado visualiza no leitor tradicional de PDF.
2. **Visão da Máquina (`Machine View`)**:
   Exibição integral de todo o conteúdo textual e metadados que o parser extrai do fluxo de objetos do documento.
3. **Visão Forense / Heatmap (`Forensic Heatmap`)**:
   Projeção na página original destacando com caixas coloridas os locais exatos onde foram encontrados textos ocultos, micro-fontes, textos transparentes ou diretivas injetadas. Cada caixa exibe:
   - Identificador do achado (`DOCF-xxxx`);
   - Regra violada (`DOC-STEG-*`, `DOC-AI-*`, `DOC-TOOL-*`);
   - Nível de severidade (`CRITICAL`, `HIGH`, `MEDIUM`);
   - Trecho exato da injeção decodificada.
4. **Visão Sanitizada (`Sanitized View`)**:
   O texto exato contido no `ReaderPayload` disponibilizado ao LLM. Permite ao auditor atestar que comandos adversariais foram removidos e que o texto está carimbado como não executável.
5. **Diferencial Humano × Máquina (`Diff View`)**:
   Comparação lado a lado com realce visual das discrepâncias e contador de tokens ocultos (`machine_only_tokens`).

---

## 5. Verificador Independente Offline (`heraclitus-forensic-verify`)

O pacote pericial deve ser auditável por ferramenta binária independente:

~~~bash
heraclitus-forensic-verify --package EvidencePackage/
~~~

Critérios de validação:

1. Conferência do digest de cada arquivo em `evidence/` e `analysis/` contra `manifest.json`;
2. Validação da assinatura digital do pacote (`proofs/signature.p7s`) e carimbo de tempo ICP-Brasil (`proofs/timestamp.tsr`);
3. Re-cálculo independente dos 6 hashes a partir dos spans preservados;
4. Verificação da prova criptográfica de inclusão Merkle no LSN do HRKL;
5. Confirmação formal da invariante `upstream_delta == 0` associada à quarentena.
