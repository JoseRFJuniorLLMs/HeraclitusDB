# SPEC-0091 — Immutable External Storage & Legal Hold Enforcement

**Status:** Draft / Proposed  
**Data:** 18/09/2026  
**Classe:** WORM / Object Lock / Legal Hold / External Durability  
**Prioridade:** P1  
**Dependências:** SPEC-0046, SPEC-0049, SPEC-0050-HRKL, SPEC-0089  
**Alvos:** heraclitus-tier, heraclitus-compliance, heraclitus-server  
**Princípio:** *Software no mesmo host não pode prometer resistência absoluta ao administrador que controla o host. Imutabilidade forte exige uma fronteira externa.*

---

## 0. Decisão

O Legal Hold atual protege o fluxo lógico do HeraclitusDB.

Esta SPEC adiciona proteção de armazenamento externo que possa impedir ou detectar destruição mesmo quando o processo principal ou seu administrador estiver comprometido.

Não usar a expressão root-proof como garantia absoluta.

## 1. Modelo de ameaça

Atacante pode possuir:

- root/admin do host;
- processo Heraclitus;
- configuração local;
- filesystem local.

Fora do domínio do atacante pode existir:

- object store com retenção;
- appliance WORM;
- conta/credencial separada;
- HSM;
- repositório remoto/air-gapped.

## 2. Backend

~~~rust
pub trait ImmutableStore {
    fn put_immutable(&self, object: ImmutableObject, retention: RetentionPolicy)
        -> Result<ImmutableReceipt, ImmutableError>;

    fn head(&self, id: &ObjectId) -> Result<ImmutableMetadata, ImmutableError>;
    fn verify_retention(&self, id: &ObjectId) -> Result<RetentionStatus, ImmutableError>;
}
~~~

## 3. Modos

~~~text
LOCAL_ONLY
REMOTE_VERSIONED
WORM_GOVERNANCE
WORM_COMPLIANCE
OFFLINE_ARCHIVE
~~~

Os nomes são capacidades. O backend concreto deve mapear para semântica real e publicar limitações.

## 4. ExternalReceipt

Após publicação:

~~~text
object_id
logical_root
physical_digest
backend_id
retention_mode
retain_until
provider_version
request_digest
response_digest
trusted_time
~~~

O receipt entra no HRKL.

## 5. Legal Hold

Ao criar hold:

1. Durable AdminIntent;
2. registrar hold local;
3. aplicar retenção externa quando configurada;
4. verificar estado do backend;
5. gravar HoldActivationReceipt;
6. Durable AdminResult.

Se política exigir WORM e o backend não confirmar, hold fica FAILED/UNKNOWN e a operação não pode ser anunciada como protegida externamente.

## 6. Remoção de hold

Deve passar pela SPEC-0089.

Pode exigir:

- two-person approval;
- role separation;
- motivo;
- ticket/process reference;
- janela temporal;
- assinatura.

Backend que não permite redução de retenção deve permanecer autoridade. O Heraclitus não deve fingir que desbloqueou fisicamente o que o store mantém bloqueado.

## 7. Integração cold tier

Esta SPEC depende da modelagem explícita de gerações frias no HRKM.

External immutable location deve ser representada de modo que:

- logical identity permaneça estável;
- múltiplas locations sejam possíveis;
- GC saiba o que pode remover;
- repack físico não altere a raiz lógica;
- retention externa seja observável.

## 8. Separação de credenciais

Credencial capaz de gravar objeto não deve necessariamente conseguir reduzir retenção ou apagar.

Preferir contas/roles separadas:

~~~text
writer
verifier
retention-admin
break-glass
~~~

Break-glass é sempre auditado e, quando possível, exige aprovação externa.

## 9. Detecção de divergência

Worker periódico verifica:

- objeto existe;
- digest físico;
- retention status;
- versão;
- receipt.

Divergência gera SecurityEvent crítico.

Não reparar silenciosamente antes de registrar a divergência.

## 10. Air-gap

Offline archive pode usar export assinado:

~~~text
ArchiveBundle
- segments
- manifests
- receipts
- proofs
- signatures
- timestamps
- catalog
~~~

Import/recheck posterior deve validar tudo antes de confiar.

## 11. Testes

1. delete local não afeta objeto WORM;
2. backend simulado recusa redução de retenção;
3. hold exige confirmação externa quando policy manda;
4. receipt adulterado falha;
5. objeto adulterado falha digest;
6. rede cai após upload antes do receipt → UNKNOWN/reconcile;
7. duas locations da mesma identidade lógica;
8. repack preserva logical root;
9. GC nunca remove objeto sob hold;
10. credencial writer não possui delete/retention admin no teste de política;
11. backend real em laboratório.

## 12. Claims

Permitido:

- Legal Hold enforced by Heraclitus policy;
- external retention verified on backend X;
- WORM capability qualified in environment Y.

Proibido sem prova:

- impossível de apagar;
- root não pode destruir;
- conformidade legal automática;
- WORM certificado sem avaliação do backend.

## 13. Definition of Done

- trait ImmutableStore;
- backend de referência;
- receipts;
- integração HRKM/cold locations;
- Legal Hold via SPEC-0089;
- reconciler;
- divergence monitor;
- testes de falha;
- exercício externo/laboratorial;
- documentação dos limites de cada modo.
