# SPEC-0086 — Government Trust & Key Management

**Status:** Draft / Proposed  
**Data:** 18/09/2026  
**Classe:** Cryptographic Trust / HSM / Multi-Tenant Key Management / Government  
**Prioridade:** P0  
**Dependências:** SPEC-0046, SPEC-0049, SPEC-0050-HRKL, SPEC-0089  
**Alvos:** heraclitus-compliance, heraclitus-crypto, heraclitus-server  
**Princípio:** *A chave que sustenta a confiança institucional não deve depender da confidencialidade de um ficheiro comum no host.*

---

## 0. Decisão arquitetural

Esta SPEC transforma o gerenciamento de chaves do HeraclitusDB numa fronteira explícita e substituível.

O core NÃO deve conhecer fabricante de HSM. O core conhece apenas um contrato de Key Provider. Implementações concretas podem usar:

- keystore de software para desenvolvimento;
- PKCS#11 para HSM físico;
- serviço KMS institucional;
- provider de teste determinístico.

Nenhuma afirmação de certificação FIPS, ICP-Brasil ou homologação de HSM pode ser derivada apenas da presença do conector. Certificação pertence ao dispositivo, configuração e ambiente efetivamente qualificados.

## 1. Objetivos

1. retirar chaves mestras de assinatura e wrapping do filesystem comum em perfis de produção;
2. permitir PKCS#11 sem dependência de um fabricante;
3. isolar material criptográfico por tenant/órgão;
4. suportar rotação, revogação e destruição auditável;
5. permitir assinatura e unwrap sem exportar a chave privada;
6. integrar aprovação dupla para operações destrutivas;
7. produzir evidência verificável da política e do provider usados.

## 2. Não objetivos

- implementar firmware de HSM;
- declarar qualquer appliance automaticamente homologado;
- substituir ICP-Brasil;
- guardar segredo dentro de logs imutáveis;
- permitir fallback silencioso de HSM para ficheiro local.

## 3. Contrato KeyProvider

~~~rust
pub trait KeyProvider: Send + Sync {
    fn provider_id(&self) -> &str;
    fn capabilities(&self) -> KeyCapabilities;

    fn generate_data_key(&self, tenant: &TenantId) -> Result<WrappedDataKey, KeyError>;
    fn unwrap_data_key(&self, key: &WrappedDataKey) -> Result<SecretBytes, KeyError>;

    fn sign(&self, key: &KeyRef, digest: &[u8]) -> Result<Signature, KeyError>;
    fn public_key(&self, key: &KeyRef) -> Result<PublicKey, KeyError>;

    fn rotate(&self, key: &KeyRef) -> Result<KeyRef, KeyError>;
    fn destroy(&self, key: &KeyRef, authz: &DestructiveAuthorization) -> Result<DestroyReceipt, KeyError>;

    fn health(&self) -> KeyProviderHealth;
}
~~~

Regra: uma operação marcada como non-exportable MUST permanecer non-exportable até o dispositivo. O wrapper Rust não pode materializar chave privada em Vec<u8> apenas para facilitar a API.

## 4. Providers

### 4.1 SoftwareKeyProvider

Permitido para:

- desenvolvimento;
- CI;
- testes de recuperação;
- instalação explicitamente classificada como software-backed.

Em production_mode, o operador MUST escolher conscientemente se aceita software-backed. Não existe fallback implícito.

### 4.2 Pkcs11KeyProvider

Requisitos mínimos:

- seleção de slot/token por configuração;
- login por mecanismo que evite senha em argumento de processo;
- sessão reutilizável com limites;
- tratamento de token removido;
- mecanismos criptográficos allowlisted;
- mapeamento estável KeyRef → object handle/label;
- timeout e circuit breaker;
- zeroização de PIN e buffers transitórios quando aplicável;
- health check que diferencie TOKEN_ABSENT, LOCKED, DEGRADED e READY.

### 4.3 RemoteKmsProvider

Opcional. Deve obedecer aos modos de soberania da SPEC-0046.

StrictAirGap + KMS externo = DENY.

## 5. Hierarquia de chaves

~~~text
Tenant Root / KEK
        |
        +-- DEK epoch 0001
        +-- DEK epoch 0002
        +-- signing key
        +-- evidence export key
~~~

Cada tenant possui domínio criptográfico independente.

Uma DEK comprometida do tenant A não pode permitir descriptografia do tenant B.

## 6. Envelope criptográfico

O payload cifrado deve carregar metadado estrutural explícito. Detecção por magic prefix do próprio plaintext não é autoridade suficiente.

~~~text
EncryptionEnvelopeV2
- version
- tenant_id
- key_id
- key_epoch
- algorithm
- nonce
- aad_digest
- ciphertext
~~~

O estado encrypted/plaintext é propriedade do envelope/record, não inferência baseada nos primeiros bytes do payload.

## 7. Rotação

A rotação cria nova época para escritas futuras. Por padrão NÃO reescreve HRKL histórico.

~~~text
epoch 7 active
rotate
epoch 8 active
historical epoch 7 remains decryptable
~~~

Re-encryption de histórico, quando permitido por política, é uma projeção/cópia física e não pode fingir que substituiu o registro canônico.

## 8. Crypto-shredding

Crypto-shredding exige:

1. verificação de Legal Hold;
2. autorização de política;
3. aprovação dupla quando configurada;
4. AdminIntent durável da SPEC-0089;
5. destruição no provider;
6. DestroyReceipt;
7. AdminResult durável.

Se o provider não puder provar o resultado, o estado é UNKNOWN, nunca SUCCESS por suposição.

## 9. Four-eyes

Para operações configuradas como críticas:

~~~text
requester != approver_1
approver_1 != approver_2
requester != approver_2
~~~

A política pode exigir papéis distintos, por exemplo Custodian + SecurityOfficer.

A aprovação é single-use, ligada ao digest exato da operação, tenant, alvo, razão e prazo.

## 10. Multi-tenancy criptográfico

TenantId deve participar de:

- AAD;
- autorização;
- namespace;
- key derivation/wrapping;
- auditoria;
- quotas;
- exportação;
- retenção;
- Legal Hold.

É proibido aceitar TenantId apenas como atributo de aplicação enquanto a chave criptográfica permanece global.

## 11. Falhas

Em perfis endurecidos:

- HSM indisponível para operação que exige HSM → fail-closed;
- key ref inexistente → fail-closed;
- mecanismo não allowlisted → fail-closed;
- provider trocado sem migração/autorização → fail-closed;
- fallback para software → proibido;
- material de chave em log → erro crítico.

## 12. Telemetria

Métricas não podem expor segredos.

Permitido:

- provider_state;
- sign_latency;
- unwrap_latency;
- session_pool_usage;
- failures_by_class;
- active_key_epoch.

Proibido:

- PIN;
- secret key bytes;
- plaintext DEK;
- atributos PKCS#11 sensíveis.

## 13. Testes obrigatórios

1. isolamento tenant A/B;
2. HSM/token removido durante operação;
3. rotação concorrente com append;
4. destruição bloqueada por Legal Hold;
5. replay de aprovação recusado;
6. operação com digest mutado após aprovação recusada;
7. production_mode sem provider válido não arranca;
8. provider indisponível não faz fallback;
9. envelope V2 não depende de magic prefix;
10. crash entre AdminIntent e destruição recupera para estado reconciliável;
11. zero segredos em logs de erro;
12. teste de interoperabilidade com SoftHSM em CI;
13. teste laboratorial com HSM real fora do CI.

## 14. Gates de aceitação

### Gate A — segurança de chave
Nenhuma chave privada de assinatura HSM-backed aparece na memória exportável da aplicação.

### Gate B — segregação
Um processo autenticado apenas como tenant A não consegue unwrap, sign ou destroy referências do tenant B.

### Gate C — recuperação
Restart durante rotação/destruição não produz dois estados simultaneamente autoritativos.

### Gate D — laboratório
Pelo menos um provider PKCS#11 real deve ser exercitado e documentado antes de qualquer claim de produção HSM.

## 15. Definition of Done

A SPEC só pode ser marcada IMPLEMENTED quando:

- trait e providers estiverem no código;
- configuração for fail-closed;
- multi-tenant keys estiverem integradas ao envelope;
- destructive operations passarem pela SPEC-0089;
- suíte de testes acima estiver verde;
- documentação operacional existir;
- houver teste com PKCS#11 real;
- STATUS.md distinguir IMPLEMENTED de EXTERNALLY QUALIFIED.
