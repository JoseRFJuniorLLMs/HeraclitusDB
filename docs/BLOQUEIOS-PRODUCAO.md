# Bloqueios de produção — SPEC-0046

Estado em **2026-08-31** (segunda ronda). Este documento existe para responder a uma pergunta
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

## Ronda de 2026-08-31 — levantamento exaustivo e o que ele apanhou

Cinco auditores independentes contra a RFC 5280 §6.1 e a RFC 3161. **50
achados crus.** Ressalva sobre o método, porque muda como se lê o número: a
fase de refutação adversarial morreu no limite de sessão (37 dos 44 agentes),
portanto só 2 achados foram testados por terceiros. Os restantes verifiquei
eu, contra o código. O `refutados: 37` que o workflow reportou é aritmética
enganadora — esses agentes **erraram**, não refutaram.

### O bloqueio total, confirmado adversarialmente

Só `sha256WithRSAEncryption` era aceite. A DOC-ICP-01.01 impõe RSA-4096 com
**SHA-512** à AC Raiz: numa hierarquia real `Raiz → AC → ACT`, o elo `Raiz→AC`
caía no ramo de recusa. **Um carimbo legítimo de uma ACT credenciada era
recusado** — e com a mensagem errada, porque o erro do elo superior é engolido
pelo `.is_ok()` da procura de âncora e reaparece como *"cadeia não chega a
nenhuma âncora configurada"*. Quem lesse isso iria mexer na pasta certa pela
razão errada.

Corrigido em `algoritmos.rs`: RSA PKCS#1v1.5 e RSASSA-PSS com SHA-256/384/512,
ECDSA P-256 com os três digests. Mais um piso de tamanho de chave — a caixa
`rsa` impõe um máximo e **nenhum mínimo**, e um módulo de 512 bits era aceite.

### As restrições eram ignoradas, não "recusadas"

Este documento dizia que a cadeia *"recusa em vez de adivinhar"*. Era verdade
para a **construção** do caminho e falso para as **restrições**. `nameConstraints`,
`pathLenConstraint` e `keyUsage.keyCertSign` eram lidos por ninguém; extensões
críticas desconhecidas eram ignoradas (§6.1.4(f) obriga a recusar); extensões
**repetidas** eram aceites (§4.2 proíbe — com duas cópias é a ordem, não a
norma, que decide qual vale). Tudo em `constraints.rs`.

### Sete correcções nas CRLs, três de segurança

Só a **primeira** CRL utilizável era consultada — o ficheiro que o `read_dir`
devolvesse primeiro era a política de revogação do órgão. `cRLSign` não era
exigido a quem assina. Delta CRLs passavam como completas. `issuingDistributionPoint`
ignorado. Sem `nextUpdate` a CRL escapava à frescura por completo. O `reasonCode`
era lido pelo último octeto sem confirmar a etiqueta. E a janela de validade
era calculada e deitada fora — chega agora ao resultado.

### O `genTime` com fracção de segundo

A RFC 3161 §2.4.2 permite-a **explicitamente**, e o `GeneralizedTime` do `der`
é DER-estrito e recusa-a. Um token de uma ACT que declarasse
`20260830143012.500Z` **nem chegava a descodificar**, e o erro falava de ASN.1
malformado. Novo tipo `GenTime`, tolerante e que preserva os milissegundos.

No mesmo bloco: o `digestAlgorithm` do `SignerInfo` não era lido e o
`messageDigest` era sempre comparado em SHA-256 (um token com `signedAttrs`
sobre SHA-512 falhava sempre); e `contentType`/`messageDigest` com dois valores
passavam, porque só o primeiro era examinado.

### Segunda passagem — o que faltava do levantamento

- **EKU (RFC 3161 §2.3).** A norma exige que o `extendedKeyUsage` seja
  **crítico** e declare o carimbo como **único** propósito. Aceitava-se
  não-crítico e acompanhado de outros: um certificado emitido para TLS que por
  acaso listasse `id-kp-timeStamping` passava a poder assinar carimbos, e a
  chave que serve um servidor web passava a servir evidência legal. Escotilha
  `eku_estrito` para uma ACT não conforme, declarada.
- **`messageImprint` fixado em SHA-256.** Recusava um carimbo legítimo com
  SHA-384/512 e impedia inspeccionar um `.tst` de terceiros — que é para o que
  o `inspect` existe. O tamanho passou também a ser confrontado com o algoritmo
  declarado.
- **CRLs embutidas no token eram descartadas.** É o que quebrava o caso
  air-gap: uma ACT que anexa a CRL ao carimbo entrega exactamente a informação
  que uma máquina sem rede nunca conseguiria ir buscar, e nós deitávamo-la fora
  para depois falhar por *"não há CRL do emissor"*. Usá-las não é confiar nelas
  — cada uma é verificada contra o emissor como qualquer outra.
- **Sem backtracking na cadeia.** Escolhia-se o primeiro certificado com o
  sujeito certo e desistia-se. Falhava no caso mais banal de uma PKI real: o
  **rollover de chave** de uma AC, em que ela tem dois certificados com o mesmo
  sujeito e o token traz os dois. O erro dizia "emissor desconhecido" — a coisa
  errada a procurar quando o emissor está ali ao lado. E a causa mais próxima
  passou a entrar na mensagem, em vez de ser engolida pelo `.is_ok()`.
- **`digestAlgorithms` do envelope vs `SignerInfo`.** A contradição entre os
  dois é a marca de um token remontado, e não era detectada.
- **Extensões críticas do `TSTInfo`** eram ignoradas.

Nota de método sobre o backtracking, porque custou três tentativas: as duas
primeiras versões do teste **passavam pela razão errada** — o `SET OF` do CMS é
canonicamente ordenado, portanto quem monta um token não escolhe a ordem do
conjunto, e um teste que não escolhe a ordem não prova backtracking nenhum. A
mutação que remove o backtracking não as derrubava. Só a terceira, que testa a
busca directamente com a ordem fixada, é que morre com a mutação.

---

## Terceira passagem — gates que ainda estavam só “disponíveis”

### O perfil de produção aceitava validação parcial

Havia três componentes implementados, mas opcionais exactamente no perfil que
não podia tratá-los como opcionais:

- sem `HERACLITUS_COMPLIANCE_CRL_DIR`, o servidor arrancava e escrevia
  `ExternalTokenVerified` com `revocation_checked=false`;
- `HERACLITUS_COMPLIANCE_SOVEREIGNTY=off` deixava o cliente HTTPS fora do
  `GuardedTsaClient` — havia guarda no código, mas produção podia não a usar;
- `HERACLITUS_COMPLIANCE_TSA_POLICY` era apenas um rótulo humano. O pedido saía
  sem `reqPolicy` e o verificador aceitava qualquer OID de política servido pela
  mesma ACT.

`production_mode=true` exige agora CRLs instaladas, soberania `controlled` e
`HERACLITUS_COMPLIANCE_TSA_POLICY_OID`. O OID vai no `TimeStampReq.reqPolicy`,
volta a ser exigido no `TSTInfo` assinado e é persistido separadamente do nome
humano no recibo. No caminho air-gap, `EvidenceAnchor.tsa_policy_oid` deixou de
receber por engano esse nome humano: agora só contém o OID observado depois da
verificação, e uma resposta que contradiga o token é recusada.

### A prova com ACT não estava ligada à qualificação

`heraclitus verify-token` existia, mas um resultado verde podia ficar num
terminal e o plano de `government_production` não o exigia. Existe agora o gate
normativo `act_interoperability`, que permanece `Inconclusive` até receber uma
atestação externa assinada, ligada ao binário exacto da release.

`qa/qualification/harness/Invoke-ActInteroperability.ps1` produz o artefacto
reproduzível: exige `.tst` real, imprint conhecido, OID esperado, trust store e
CRLs; regista também SHA-256 do servidor, da CLI, do token e de todo o material
de confiança usado. O script produz evidência — não assina a própria aprovação.

---

## Por resolver — dependências externas ainda reais

### A. As âncoras ICP-Brasil reais não estão instaladas

> **O que passou a existir para tornar este passo seguro:**
> `heraclitus trust-store <dir>` lista as âncoras instaladas com a impressão
> digital SHA-256 de cada uma, e mostra o **motivo** de cada ficheiro recusado
> — motivo que já era calculado e não era mostrado a ninguém. Sem isto, a única
> forma de saber o que estava na raiz de confiança era ler DER à mão, e um
> operador que não consegue inspeccionar a raiz de confiança não consegue
> afirmar que ela está certa. Essa afirmação é o que a conformidade lhe exige.


O trust store está vazio nesta máquina. **Só o órgão pode povoá-lo**: as raízes
têm de vir do canal oficial do ITI, com a impressão digital conferida fora de
banda. Instalar uma raiz que o software trouxe consigo destruiria o sentido de
§11 — a confiança que interessa é a que o operador declarou.

Fonte operacional: [Repositório da AC Raiz do ITI](https://www.gov.br/iti/pt-br/assuntos/repositorio/repositorio-ac-raiz).
O próprio ITI publica também pacotes de certificados e hashes para conferência;
a instalação continua a ser uma decisão do órgão, não do binário.

Enquanto estiver vazio, `production_mode = true` **não arranca**, por desenho.

### B. Interoperabilidade com uma ACT credenciada não está provada

> **O que passou a existir:** `heraclitus verify-token <ficheiro.tst>
> --trust-store <dir> --crl-dir <dir> --imprint <hex>
> --policy-oid <oid>` pega num `.tst`
> emitido por uma ACT e diz se este verificador o aceita — sem pôr o sistema a
> ancorar em produção, que era a única forma de o testar. Sem `--imprint` o
> relatório **diz** que o carimbo não foi ligado a conteúdo nenhum, em vez de
> calar; um carimbo válido sobre um conteúdo desconhecido não prova nada sobre
> nenhum documento.
>
> A ronda de 2026-08-31 fechou a maior parte do que faria um token real
> falhar (SHA-384/512, PSS, fracção de segundo, `digestAlgorithm`). O que
> falta é o token.


Os testes usam uma PKI sintética com a mesma estrutura. Um `.tst` emitido por
uma ACT homologada é evidência de laboratório e entra pela SPEC-0049. Até lá, o
que está provado é que o verificador aceita o que deve e recusa o que deve
**contra uma PKI que este repositório gera** — o que não é a mesma afirmação.

Riscos concretos que só um token real expõe: `SHA256withRSA` com parâmetros que
a PKI de teste não gera, cadeias com intermédios a mais, `signedAttrs` com
atributos opcionais que o parser não espera.

### C. Sem `policyMapping` nem `policyConstraints`

`nameConstraints` **passou a ser imposto** (ver acima); esta entrada dizia que
não era preciso e estava errada. O que continua por fazer é o processamento de
políticas de certificado (§6.1.2/§6.1.4 (a)-(e)): `certificatePolicies`,
`policyMappings` e `policyConstraints` não são interpretados. Um
`certificatePolicies` marcado **crítico** faz agora recusar, o que é o
comportamento seguro, com escotilha por OID declarada.

O `rollover` de chave deixou de pertencer a esta entrada: a construção do
caminho faz backtracking e o teste fixa a ordem dos candidatos directamente.
Uma mutação que reduz o laço ao primeiro candidato derruba esse teste.

### D. Atestações externas (SPEC-0049)

Fora do alcance de qualquer commit.

### E. O que ficou por fazer do levantamento, e porquê

Não são bloqueios; são endurecimento que não escolhi fazer nesta ronda. Ficam
nomeados para que a decisão seja visível em vez de a lacuna ser descoberta.

| item | porque não agora |
|---|---|
| `ESSCertID`/`ESSCertIDv2` (RFC 5035) | Amarra o token a um certificado em concreto. A assinatura sobre os `signedAttrs` já é feita pela chave do certificado e a cadeia já valida; isto protege contra uma substituição específica. Endurecimento real, não bloqueio. |
| `signedAttrs` recodificados da estrutura | O `der` reordena o `SET OF` ao descodificar. Para um token conforme a DER — que é canónico — a recodificação é idêntica. O risco é com BER não canónico. |
| `TSTInfo.tsa` vs sujeito do certificado | A RFC 3161 trata o campo como informativo. |
| `CRLDistributionPoints` vs CRL usada | O `issuingDistributionPoint` já é verificado, que é o lado que a CRL declara. |
| Cache de revogação | Desempenho. A CRL é reverificada por certificado e por token. |
| Comparação de nomes por RFC 4518 | Faz-se por igualdade de bytes DER, que é o que a generalidade das implementações faz. Recusa de mais, nunca de menos. |
| `policyMapping`/`policyConstraints` | Ver **C**. |

---

## Como um operador liga isto

```bash
export HERACLITUS_COMPLIANCE=1
export HERACLITUS_COMPLIANCE_TSA_URL=https://act.exemplo.gov.br/tsa
export HERACLITUS_COMPLIANCE_TSA_POLICY_OID=2.16.76.x.y
export HERACLITUS_COMPLIANCE_TRUST_STORE=/etc/heraclitus/ancoras
export HERACLITUS_COMPLIANCE_CRL_DIR=/etc/heraclitus/crls
export HERACLITUS_COMPLIANCE_CRL_MAX_STALENESS=0
export HERACLITUS_COMPLIANCE_SOVEREIGNTY=controlled
```

Verificação forense com a cadeia validada:

```bash
heraclitus verify-receipts --dir /var/lib/heraclitus/log --trust-store /etc/heraclitus/ancoras --crl-dir /etc/heraclitus/crls --policy-oid 2.16.76.x.y
```

Sem `--trust-store` o relatório continua **inconcluso por construção**, e agora
diz porquê em vez de dizer que a build não sabe validar.
