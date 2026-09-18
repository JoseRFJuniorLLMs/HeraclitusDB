# SPEC-0087 — Forensic Evidence Package & Chain of Custody

**Status:** Draft / Proposed  
**Data:** 18/09/2026  
**Classe:** Digital Forensics / Evidence / Chain of Custody / Judicial Export  
**Prioridade:** P0  
**Dependências:** SPEC-0046, SPEC-0048, SPEC-0049, SPEC-0050-HRKL, SPEC-0086, SPEC-0089  
**Novo crate recomendado:** heraclitus-forensic  
**Princípio:** *Exportar bytes não é exportar evidência. Evidência precisa carregar origem, integridade, história e método de verificação.*

---

## 0. Decisão arquitetural

A SPEC-0048 define o plano forense. Esta SPEC transforma essa visão em contrato implementável para pacote de evidência, cadeia de custódia e verificação independente.

O pacote deve continuar verificável fora do HeraclitusDB.

O verificador MUST funcionar sem acesso ao banco original para tudo que estiver contido no pacote.

## 1. Referência jurídica

O perfil gov-br deve permitir documentar cadeia de custódia compatível com os requisitos aplicáveis do Código de Processo Penal, especialmente arts. 158-A a 158-F, sem afirmar que software, sozinho, cria admissibilidade judicial automática.

A implementação registra fatos técnicos. A valoração jurídica pertence à autoridade competente.

## 2. Estrutura do pacote

~~~text
EvidencePackage/
├── manifest.json
├── manifest.sha256
├── evidence/
│   ├── object-000001.bin
│   └── ...
├── provenance/
│   ├── custody.jsonl
│   ├── access.jsonl
│   └── transformations.jsonl
├── proofs/
│   ├── merkle.json
│   ├── hrkl-range.json
│   ├── timestamp.tsr
│   └── signature.p7s
├── certificates/
│   └── ...
├── sbom/
│   └── exporter.cdx.json
└── report/
    └── technical-report.pdf
~~~

PDF é uma apresentação humana. manifest.json é a autoridade estruturada do pacote.

## 3. EvidenceManifest

~~~rust
pub struct EvidenceManifest {
    pub schema_version: String,
    pub package_id: String,
    pub case_id: Option<String>,
    pub tenant_id: String,

    pub source_database_id: String,
    pub source_build: BuildIdentity,
    pub lsn_range: LsnRange,
    pub hlc_range: HlcRange,

    pub objects: Vec<EvidenceObject>,
    pub merkle: MerkleEvidence,
    pub custody_digest: DigestSet,
    pub export_identity: PrincipalIdentity,
    pub export_reason: String,

    pub created_at_claimed: String,
    pub trusted_timestamps: Vec<TrustedTimestampRef>,
    pub signatures: Vec<SignatureRef>,
}
~~~

## 4. Hashes

Internamente o HeraclitusDB pode continuar usando BLAKE3.

Para interoperabilidade do pacote, cada objeto MUST incluir pelo menos:

- BLAKE3;
- SHA-256.

Nenhuma substituição é implícita. Os dois digests identificam os mesmos bytes.

## 5. Prova de origem HRKL

Quando possível, o pacote contém:

- LSN;
- segmento/generation;
- digest lógico;
- Merkle root;
- proof path;
- versão do formato;
- digest físico opcional;
- receipt de tier/cold storage quando pertinente.

A prova deve distinguir:

~~~text
canonical logical identity
!=
physical representation
~~~

Compactação, codec e localização podem mudar sem fingir que o evento canônico mudou.

## 6. Cadeia de custódia

CustodyEvent é append-only.

~~~rust
pub struct CustodyEvent {
    pub event_id: String,
    pub evidence_id: String,
    pub action: CustodyAction,
    pub principal: PrincipalIdentity,
    pub authority: Option<String>,
    pub reason: String,
    pub source: String,
    pub destination: Option<String>,
    pub claimed_time: String,
    pub trusted_time_ref: Option<String>,
    pub prev_digest: [u8; 32],
}
~~~

A cadeia deve registrar ao menos:

- coleta/ingestão;
- preservação;
- acesso privilegiado;
- exportação;
- transferência;
- cópia;
- transformação;
- verificação;
- descarte autorizado de chave, quando aplicável.

Leitura comum de baixa sensibilidade pode ser agregada por política, mas operações forenses/administrativas privilegiadas MUST ser individualmente auditáveis.

## 7. Transformações

Qualquer transformação cria novo objeto derivado.

~~~text
original object
   |
   +--> normalized copy
   +--> redacted copy
   +--> transcoded copy
~~~

O derivado nunca substitui silenciosamente o original.

Cada transformação inclui:

- algoritmo;
- versão;
- parâmetros;
- input digests;
- output digests;
- principal/processo executor.

## 8. Tempo confiável

O pacote pode conter:

1. tempo local alegado;
2. HLC do Heraclitus;
3. carimbo RFC 3161 verificado;
4. referência de ACT/chain.

Nenhum campo local deve ser rotulado como trusted timestamp apenas por vir do relógio do host.

## 9. Assinatura

O pacote deve poder ser assinado por chave institucional via SPEC-0086.

Assinar significa assinar o digest canônico do manifest, não o PDF renderizado isoladamente.

PDF pode receber assinatura adicional, mas ela não substitui a assinatura do manifesto estruturado.

## 10. Redação e LGPD

Exportação pode produzir cópia redacted/pseudonymized.

Regras:

- original preservado quando legalmente devido;
- derivado referencia original por digest;
- campos removidos ficam declarados;
- policy id e versão entram no manifest;
- não existe anonimização declarada apenas porque um campo foi mascarado.

## 11. Verificador independente

Criar CLI:

~~~text
heraclitus evidence verify package.zip
~~~

Saída mínima:

~~~text
PACKAGE STRUCTURE      PASS
OBJECT DIGESTS         PASS
CUSTODY CHAIN          PASS
MERKLE PROOF           PASS
TIMESTAMP              PASS / NOT PRESENT / UNVERIFIED
SIGNATURE              PASS / NOT PRESENT / UNVERIFIED
CERTIFICATE CHAIN      PASS / EXTERNAL TRUST REQUIRED
OVERALL TECHNICAL      VERIFIED / PARTIAL / FAILED
~~~

Nunca transformar ausência de confiança externa em PASS.

## 12. Relatório técnico

Comando sugerido:

~~~text
heraclitus evidence report PACKAGE --pdf report.pdf
~~~

O PDF deve exibir:

- identificador do pacote;
- escopo;
- hashes;
- timeline;
- custódia;
- verificações realizadas;
- limitações;
- QR code ou código de verificação.

O QR não deve conter segredo nem depender obrigatoriamente de Internet.

## 13. Testes obrigatórios

1. mutação de um byte do objeto → FAIL;
2. mutação de custody event → FAIL;
3. remoção de evento intermediário → FAIL;
4. Merkle proof de outro segmento → FAIL;
5. timestamp inválido → FAIL;
6. pacote sem ACT → PARTIAL, nunca PASS completo;
7. assinatura válida com certificado não confiável → UNVERIFIED;
8. pacote verifica offline;
9. PDF pode ser regenerado do manifest sem alterar a prova;
10. redaction produz derivado, não sobrescreve original;
11. export crash não deixa pacote marcado COMPLETE;
12. replay de export authorization é recusado.

## 14. Gates

### Gate A — self-contained
O verificador consegue validar hashes, encadeamento e Merkle offline.

### Gate B — adversarial
100 mutações dirigidas em manifest/proofs/objects devem ser detectadas.

### Gate C — external trust
Um carimbo real de ACT só pode aparecer como VERIFIED depois de teste externo da cadeia correspondente.

### Gate D — reproducibilidade
Dado o mesmo conjunto de objetos e política, o manifest canônico produz o mesmo digest, excetuando campos explicitamente não determinísticos separados da área assinada.

## 15. Definition of Done

- crate heraclitus-forensic existente;
- EvidenceManifest versionado;
- CLI export/verify;
- SHA-256 + BLAKE3;
- prova HRKL/Merkle;
- custody chain encadeada;
- suporte a timestamp/assinatura;
- relatório PDF derivado;
- testes adversariais;
- documentação de limites jurídicos;
- integração com SPEC-0049 para qualificação independente.
