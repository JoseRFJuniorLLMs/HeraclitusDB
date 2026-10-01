# SPEC-0092 — Document & LLM Injection Firewall

**Status:** Implemented core library / integration qualification pending  
**Date:** 01/10/2026  
**Scope:** Heraclitus Sentinel + Agent Policy Gateway

## 1. Problem

Documents consumed by AI systems are untrusted input. A PDF, office document, e-mail, HTML page, OCR result, header, footer, annotation or metadata field may contain machine-readable instructions that a human reviewer does not see.

Prompt-injection defense therefore cannot be a blacklist of phrases. The system must preserve the original evidence, compare human-visible and machine-visible representations, quarantine suspicious artifacts, sanitize what is sent to readers and prevent document text from acquiring operational authority.

## 2. Security invariant

```text
UNTRUSTED_DOCUMENT
      |
      v
   DATA_ONLY
      |
      +--> may be summarized / classified
      |
      X--> may NOT become SYSTEM/POLICY/TOOL authority

Detector miss
      |
      v
Agent Policy Gateway
      |
      +--> identity binding
      +--> parameter binding
      +--> HITL when required
      +--> fail closed
```

The document reader and the privileged executor are separate security domains.

## 3. Implemented core

The canonical implementation is:

`crates/heraclitus-sentinel/src/document_security.rs`

It provides:

- structural spans with page, bbox, page bbox, font size, colors, opacity, clipping, image occlusion, transform scale, rotation and source region;
- human-visible vs machine-visible differential;
- SHA-256 for original bytes, human view, machine view, normalized view, hidden content and sanitized view;
- explainable findings rather than an opaque numeric risk score;
- deterministic rules for white-on-white/micro-font, low opacity, off-page/clipped/behind-image text, Unicode invisibles/bidi controls, token fragmentation, header/footer injection, metadata injection, model-instruction language and tool coercion;
- a pluggable `SemanticInjectionClassifier` boundary;
- canonical document-security events;
- fail-closed `ReaderPayload` with `trust=UNTRUSTED_DOCUMENT`, `authority=DATA_ONLY` and `tools_allowed=false`.

## 4. Canonical events

```text
document.hidden_text.detected
document.obfuscation.detected
document.prompt_injection.detected
document.tool_coercion.detected
document.quarantined
document.sanitized.created
```

Hosts SHOULD persist these as derived Sentinel evidence with the original document digest, page, rule id and finding id.

## 5. Differential model

For every document, the system maintains:

```text
Original bytes
Human-visible text
Machine-extracted text
Normalized text
Hidden/machine-only text
Sanitized reader text
```

A non-empty machine-only delta is not automatically malicious, but it is observable evidence. High-confidence concealment combined with instruction/tool-coercion findings is quarantine-worthy.

## 6. Detection coverage

Rules currently defined:

| Rule | Meaning |
|---|---|
| DOC-STEG-001 | visual concealment / micro-font |
| DOC-STEG-002 | invisible or bidi Unicode |
| DOC-STEG-004 | near-transparent text |
| DOC-GEOM-001 | off-page, clipped, behind image or tiny transform |
| DOC-FRAG-003 | artificial token fragmentation |
| DOC-HDR-001 | AI-directed instruction in header/footer |
| DOC-META-001 | AI-directed instruction in metadata |
| DOC-AI-003 | model-authority coercion |
| DOC-TOOL-001 | tool call / mutation / exfiltration coercion |
| DOC-SEM-001 | semantic-classifier finding |

## 7. Reader/executor separation

A reader LLM receives only `ReaderPayload`. The payload is incapable, by contract, of granting tools. Privileged effects MUST flow through the Agent Policy Gateway.

A UI displaying `DENY` is not enough. Qualification requires proving that a denied request generated no protected side effect, e.g. `upstream_delta=0`.

## 8. Visualization contract

A forensic UI SHOULD expose:

1. **Human view** — normal rendering.
2. **Machine view** — all extracted content.
3. **Forensic view** — page overlay/heatmap with rule, severity, bbox and extracted payload.
4. **Sanitized view** — exact reader payload.
5. **Human vs Machine diff** — machine-only token count.
6. **Causal graph** — document → finding → policy → effect/no-effect → evidence.
7. **Evidence state** — hashes, LSN/HLC, Merkle inclusion and offline-verification state when integrated.

## 9. What is not claimed

The core module is parser-agnostic. It does not itself parse arbitrary PDFs, execute OCR, validate PDF syntax, or prove that every steganographic representation has been discovered.

NFKC/advanced Unicode canonicalization and parser-specific PDF object inspection remain responsibilities of the ingestion adapter until a dedicated document-parser crate is qualified.

No semantic classifier is infallible. Security relies on defense in depth and the authority boundary, not on perfect detection.

## 10. Qualification gates

A production adapter must demonstrate at least:

- real PDF text-layer extraction and page geometry;
- header/footer/annotation/metadata coverage;
- control samples with legitimate academic references to prompt injection;
- low-opacity, same-color, micro-font, clipping, off-page, zero-width, bidi, fragmentation and tool-coercion cases;
- detector-MISS test where Policy Gateway still yields zero protected side effects;
- byte-for-byte preservation of the original;
- reproducible sanitized payload;
- persisted Sentinel events linked to the original document hash;
- evidence bundle/offline verification when the forensic plane is enabled.

## 11. Reference POC

The independent `JoseRFJuniorLLMs/STF` POC demonstrates the visualization and synthetic judicial scenarios. It is not an official STF system and uses no real STF data or network.
