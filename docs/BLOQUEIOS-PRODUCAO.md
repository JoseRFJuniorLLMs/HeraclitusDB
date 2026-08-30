# Bloqueios de produção — SPEC-0046

Estado em **2026-08-30**. Este documento existe para responder a uma pergunta
só: *o que impede `production_mode = true` de arrancar, e de quem é cada
bloqueio*.

A regra que o governa: **um bloqueio só sai desta lista quando o código o
resolve, não quando a mensagem de erro deixa de o mencionar.** Antes desta
ronda, três das mensagens da guarda de produção diziam que a build não
implementava HTTPS nem validação CMS/X.509 — e implementava desde o Marco 0.
Mensagens que envelhecem sozinhas são piores do que nenhuma: quem as lê corrige
a coisa errada.

---

## Resolvidos nesta ronda

### 1. `TimeStampResp` nunca era parseada — uma RECUSA da ACT ficava como recibo

O mais grave dos bloqueios, e não estava na lista antes de se olhar para o
código. O `HttpTsa::stamp` devolvia **o corpo HTTP inteiro** e o worker
gravava-o como se fosse o carimbo. Pela RFC 3161 §2.4.2 esse corpo é uma
`TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken OPTIONAL }`,
não um `ContentInfo`. Consequências, todas silenciosas:

- Uma ACT que **recusa** responde `status=2 (rejection)` e **não anexa token
  nenhum**. Essa recusa era persistida no manifesto como evidência legal.
- `revocationWarning`/`revocationNotification` — a ACT a dizer que a *sua
  própria chave* está a ser revogada — passavam da mesma forma.
- O que ficava em disco nunca poderia ser verificado por um verificador CMS,
  porque não era um token.

Agora `rfc3161.rs` tem `TimeStampResp`, `PkiStatusInfo` e `PkiStatus`, e
`granted_token()` devolve `Err` para tudo o que não seja `granted` ou
`grantedWithMods`, com os bits de `failInfo` por nome (`unacceptedPolicy`,
`timeNotAvailable`, …) — um operador que vê `unacceptedPolicy` sabe o que
corrigir; um que vê "recusado" não sabe nada.

`grantedWithMods` é aceite. Não é confiança na ACT: tudo o que ela possa ter
alterado e que importe — imprint, nonce, política, certificado — é reverificado
a seguir, e o verificador recusa se não bater.

### 2. `SecureTsaClient` não implementava `TsaClient`

Estava escrito e testado, e **o worker não o podia usar** — o `run_worker` só
aceita um `dyn TsaClient`. É a assinatura do modo de falha que este projeto já
nomeou: *implementado, testado, nunca chamado*.

Agora implementa. E a verificação acontece **dentro do `stamp`**, antes de o
token sair do cliente: um carimbo que não encadeie até uma âncora nunca chega a
ser escrito em disco. A diferença é entre "não temos carimbo desta marca" e
"temos um recibo que não vale nada e ninguém sabe".

O nonce que vai no pedido é comparado com o que volta, e os octetos esperados
passam pelo mesmo codificador/descodificador DER que produziu o pedido — a
forma mínima com complemento para dois tem casos de fronteira, e um nonce que
não bate faz o carimbo ser recusado como repetição contra uma ACT real.

### 3. Não existia estado que dissesse "verificado"

`TimestampValidationState` tinha três variantes e nenhuma podia significar
"a cadeia foi validada". Existe agora `ExternalTokenVerified`, e **só um cliente
com verificador instalado a pode produzir**.

O `anchor()` recusa escrever um recibo cujo cliente declare `Verified` mas não
saiba devolver o `genTime` verificado. As duas afirmações contradizem-se, e a
contradição não se resolve escrevendo o recibo à mesma: ficaria em disco um
estado "verificado" com hora de autoridade ausente — a combinação que um
auditor lê como prova e que não prova nada.

### 4. Nada reverificava um recibo que se declara verificado

Duas funções novas, com o mesmo princípio: **uma alegação de "verificado" não se
acredita, re-verifica-se.**

- `verify_receipt_with_verifier` — reverifica o token contra as âncoras
  instaladas. Um recibo que se declarava verificado e que agora não confirma dá
  `Err`: ou as âncoras mudaram, ou o token foi substituído.
- `import_deferred_response_with_verifier` — no caminho de air-gap, a resposta
  vem de **fora** da fronteira de confiança. `import_deferred_response` (sem
  verificador) passou a **recusar** uma resposta que se declare verificada, em
  vez de a registar.

O `verify_receipt` simples continua a devolver `CommitmentOnly` para esse
estado, e é deliberado: devolver `AuthorityVerified` com base no campo do
próprio recibo faria o verificador repetir a alegação que devia estar a testar.

### 5. O worker usava `HttpTsa` e nada instanciava o verificador

`compliance_tsa_mode = "https"` constrói agora um `SecureTsaClient` com
verificador, a partir de `HERACLITUS_COMPLIANCE_TRUST_STORE`. O servidor
**recusa arrancar** se a pasta não tiver âncoras utilizáveis: arrancar assim
daria um servidor que aceita carimbos que ninguém autenticou e os grava como
recibos.

**Armadilha corrigida pelo caminho:** `HERACLITUS_COMPLIANCE_TSA_URL` forçava o
modo para `"http"` mesmo com um URL `https://`. Quem pedia TLS recebia o cliente
em claro, e só descobria na primeira tentativa de carimbo, com uma mensagem
sobre o esquema que não apontava para a causa. O modo passa a vir do esquema.

### 6. `GuardedTsaClient` não estava instalado

Estava incompatível por construção — `EgressEndpoint::validate()` exige
`https` e o cliente antigo só falava HTTP. Com o §10 feito, a incompatibilidade
acabou.

O servidor não tinha (e continua a não ter) uma superfície de configuração de
soberania. `compliance_sovereignty_mode` é **`off` por defeito, e isso é
deliberado**: a alternativa seria instalar a guarda com uma política que
autoriza tudo, o que daria a *aparência* de um controlo de egresso sem o
controlo — pior do que não ter guarda, porque um auditor veria o componente na
configuração e concluiria que alguém decide o que sai.

`controlled` autoriza exactamente um destino, derivado do **mesmo URL** que o
cliente vai usar; configurá-lo à parte deixaria a allowlist autorizar um host e
o cliente ligar a outro. `strict-air-gap` nega o carimbo em linha e audita a
negação — não é um erro de configuração, é a configuração a fazer o que diz.

### 7. Revogação não era consultada

Era a lacuna mais citada, e a única que estava honestamente declarada:
`VerifiedTimestamp::revocation_checked` era sempre `false`.

O módulo `crl.rs` faz a consulta **offline**, por ficheiro. Não é OCSP de
propósito: OCSP é uma ligação de rede por verificação, e traria rede para dentro
do caminho que tem de continuar a funcionar num órgão em air-gap, anos depois,
quando o respondedor da AC já não existir. Uma CRL é um ficheiro assinado —
copia-se, arquiva-se **com** a evidência, e verifica-se sem rede.

A parte que não é uma comparação de datas, e é a que interessa:

| situação | decisão | porquê |
|---|---|---|
| revogado **antes** do `genTime` | recusa | a autoridade já tinha dito que a chave não valia |
| revogado **depois**, motivo comum | **aceita** | um carimbo emitido enquanto o certificado valia continua a provar a hora — é a razão de existir de um carimbo |
| `keyCompromise` / `cACompromise`, **em qualquer data** | recusa | a data de revogação é quando a AC *soube*, não quando a chave foi comprometida; quem tem a chave carimba com o `genTime` que quiser |

A terceira linha é o que impede isto de ser teatro. Tratar um `keyCompromise`
como "revogado depois, portanto vale" é exactamente o erro que um atacante com
a chave explora. Está validado por mutação: pôr `invalida_retroativamente` a
devolver `false` derruba `key_compromise_invalida_o_carimbo_mesmo_tendo_sido_revogado_depois`
e **só** esse teste.

Frescura é imposta (`CrlPolicy::max_staleness`, default zero). Uma CRL em falta
para um emissor **falha a verificação** em vez de a dar por limpa: "pedi consulta
de revogação e não a consegui fazer" não pode devolver um resultado que se leia
como limpo.

A âncora não é consultada — uma raiz auto-emitida não é revogada por uma CRL
sua; retirá-la da confiança é apagar o ficheiro da pasta, que é o mecanismo que
o operador tem e vê.

### 8. Disco

O `D:` estava a 98%. Está a **54% (323 GB livres)**. Não era um bloqueio de
código; fica registado por ter estado na lista.

---

## Por resolver — e nenhum destes se resolve com código

### A. As âncoras ICP-Brasil reais não estão instaladas

O trust store está vazio nesta máquina. **Só o órgão pode povoá-lo**: as raízes
têm de vir do canal oficial do ITI, com a impressão digital conferida fora de
banda. Instalar uma raiz que o software trouxe consigo destruiria o sentido de
§11 — a confiança que interessa é a que o operador declarou.

Enquanto estiver vazio, `production_mode = true` **não arranca**, por desenho.

### B. Interoperabilidade com uma ACT credenciada não está provada

Os testes usam uma PKI sintética com a mesma estrutura. Um `.tst` emitido por
uma ACT homologada é evidência de laboratório e entra pela SPEC-0049. Até lá, o
que está provado é que o verificador aceita o que deve e recusa o que deve
**contra uma PKI que este repositório gera** — o que não é a mesma afirmação.

Riscos concretos que só um token real expõe: `SHA256withRSA` com parâmetros que
a PKI de teste não gera, cadeias com intermédios a mais, `signedAttrs` com
atributos opcionais que o parser não espera.

### C. Sem `nameConstraints` nem `policyMapping`

A cadeia é por correspondência exacta de nomes em DER com `basicConstraints`.
Chega para a topologia raiz → AC → ACT da ICP-Brasil. Para uma malha com
cross-certificados não chega — e **recusa em vez de adivinhar**.

### D. Atestações externas (SPEC-0049)

Fora do alcance de qualquer commit.

---

## Como um operador liga isto

```bash
export HERACLITUS_COMPLIANCE=1
export HERACLITUS_COMPLIANCE_TSA_URL=https://act.exemplo.gov.br/tsa
export HERACLITUS_COMPLIANCE_TRUST_STORE=/etc/heraclitus/ancoras
export HERACLITUS_COMPLIANCE_CRL_DIR=/etc/heraclitus/crls
export HERACLITUS_COMPLIANCE_CRL_MAX_STALENESS=0
export HERACLITUS_COMPLIANCE_SOVEREIGNTY=controlled
```

Verificação forense com a cadeia validada:

```bash
heraclitus verify-receipts --dir /var/lib/heraclitus/log --trust-store /etc/heraclitus/ancoras --crl-dir /etc/heraclitus/crls
```

Sem `--trust-store` o relatório continua **inconcluso por construção**, e agora
diz porquê em vez de dizer que a build não sabe validar.
