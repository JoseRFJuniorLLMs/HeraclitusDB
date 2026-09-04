# SPEC-new/STATUS.md — Estado real dos documentos SPEC-new

**Gerado:** 2026-07-08/09 · **Método:** auditoria automatizada multi-agente
(extração de afirmações + verificação adversarial), cada afirmação verificada
com grep/leitura contra o código real em `crates/*/src`. `graphify-out/`
excluído (é cache, dá falsos positivos).

> **TL;DR:** os documentos em `SPEC-new/` são **PROPOSTAS (RFCs), não
> implementação**. Vários vendem como "código real", "auditado", "CONGELADO" ou
> "APROVADO" componentes que **não existem em nenhum crate**. Este ficheiro lista
> cada afirmação falsa/enganosa com a evidência. O estado real da plataforma e o
> roteiro estão em [../PLANO-SPECS.md](../PLANO-SPECS.md).

## BLOQUEIOS DE PRODUÇÃO — 2026-08-30 (5)

Esta nota **substitui** três afirmações da nota "MARCO 0" abaixo, que
envelheceram nesta mesma ronda: (a) "o `SecureTsaClient` ainda não substituiu o
`HttpTsa` no worker" — substituiu; (b) "revogação não é consultada" — passou a
ser; (c) "falta a decisão de trocar o cliente no worker" — foi tomada, e é
opt-in por configuração. O relatório completo está em
[../../BLOQUEIOS-PRODUCAO.md](../../BLOQUEIOS-PRODUCAO.md).

### O bloqueio que não estava na lista, e era o pior

`TimeStampResp` **nunca era parseada em lado nenhum**. O `HttpTsa::stamp`
devolvia o corpo HTTP inteiro e o worker gravava-o como se fosse o carimbo. Pela
RFC 3161 §2.4.2 esse corpo é uma `TimeStampResp`, não um `ContentInfo`, e o
`PKIStatus` nunca era lido. Consequência: **uma ACT que RECUSA (`status=2`, sem
token nenhum anexado) via a sua recusa persistida no manifesto como evidência
legal.** O mesmo para `revocationWarning`/`revocationNotification` — a ACT a
avisar que a sua própria chave está a ser revogada.

Não apareceu na auditoria anterior porque essa procurou por peças em falta, e
esta é uma peça **presente e errada**: havia um `TimeStampReq`, o código
compilava, os testes passavam, e o campo que decidia tudo nunca era lido.

### O que ficou ligado

| bloqueio | antes | agora |
|---|---|---|
| resposta da ACT | corpo HTTP gravado como token | `TimeStampResp` + `PKIStatus` + `failInfo` por nome |
| `SecureTsaClient` | escrito, testado, **sem implementar `TsaClient`** | implementa; verifica **dentro** do `stamp` |
| estado "verificado" | não existia variante | `ExternalTokenVerified`, só produzível com verificador |
| reverificação | nenhuma | `verify_receipt_with_verifier`, `import_deferred_response_with_verifier` |
| worker | `HttpTsa` fixo | `mode=https` → cliente com cadeia validada |
| `GuardedTsaClient` | incompatível por construção | instalável, `off` por defeito |
| revogação | `revocation_checked` sempre `false` | CRL offline, com semântica de carimbo |

### As decisões que custaram, e as objeções que ficaram

- **`grantedWithMods` é aceite.** Não é confiança na ACT: tudo o que ela possa
  ter alterado e que importe — imprint, nonce, política, certificado — é
  reverificado a seguir e recusado se não bater. Aceitar aqui é adiar a decisão
  para quem a pode tomar com prova.
- **A revogação NÃO é uma comparação de datas.** Revogado antes do `genTime`
  recusa; revogado *depois* com motivo comum **aceita** (um carimbo emitido
  enquanto o certificado valia continua a provar a hora — é a razão de existir
  de um carimbo); `keyCompromise`/`cACompromise` recusa **em qualquer data**,
  porque a `revocationDate` é quando a AC soube, não quando a chave foi
  comprometida, e quem tem a chave carimba com o `genTime` que quiser. Esta
  terceira regra é o que impede o módulo de ser teatro, e está validada por
  mutação: `invalida_retroativamente → false` derruba um teste, e só esse.
- **CRL de ficheiro, não OCSP.** OCSP é uma ligação de rede por verificação, e
  traria rede para dentro do caminho que tem de funcionar em air-gap anos
  depois, quando o respondedor da AC já não existir. A contrapartida assumida é
  a frescura, imposta por `CrlPolicy::max_staleness` (default zero).
- **Uma CRL em falta FALHA a verificação.** "Pedi consulta de revogação e não a
  consegui fazer" não pode devolver um resultado que se leia como limpo.
- **A guarda de soberania fica `off` por defeito.** Instalá-la com uma política
  que autoriza tudo daria a *aparência* de um controlo de egresso sem o
  controlo — pior do que não ter guarda, porque um auditor veria o componente na
  configuração e concluiria que alguém decide o que sai.
- **Objecção que mantenho:** não bastava pôr a guarda de `production_mode` a
  devolver `Ok`. Três das suas mensagens diziam que a build não implementava
  HTTPS nem validação CMS/X.509 — e ambos existiam desde o Marco 0. Corrigir só
  a mensagem teria deixado produção a arrancar com o cliente em claro. **Um
  bloqueio só sai da lista quando o código o resolve, não quando a mensagem
  deixa de o mencionar.**

### Armadilha de configuração corrigida pelo caminho

`HERACLITUS_COMPLIANCE_TSA_URL=https://…` forçava `compliance_tsa_mode` para
`"http"`. Quem pedia TLS recebia o cliente em claro e só descobria na primeira
tentativa de carimbo, com um erro sobre o esquema que não apontava para a causa.
O modo passa a vir do esquema do URL.

### O que continua por fazer, e não se resolve com código

- **As âncoras ICP-Brasil reais não estão instaladas.** Só o órgão as pode
  instalar, do canal oficial do ITI, com a impressão digital conferida fora de
  banda. Enquanto o trust store estiver vazio, `production_mode = true` **não
  arranca** — por desenho, não por acidente.
- **Interoperabilidade com uma ACT credenciada não está provada.** Os testes
  usam uma PKI sintética com a mesma estrutura. Um `.tst` real é evidência de
  laboratório e entra pela SPEC-0049. Riscos que só um token real expõe:
  `SHA256withRSA` com parâmetros que a PKI de teste não gera, cadeias com
  intermédios a mais, `signedAttrs` com atributos opcionais inesperados.
- **Sem `nameConstraints` nem `policyMapping`.** Chega para raiz → AC → ACT;
  para uma malha com cross-certificados não chega, e **recusa em vez de
  adivinhar**.
- **Atestações externas (SPEC-0049)** — fora do alcance de qualquer commit.

### Validação

- `heraclitus-compliance`: **87 testes unitários** (eram 79). Os 8 novos cobrem
  a revogação: CRL limpa, revogado antes, revogado depois, `keyCompromise`, CRL
  em falta, CRL expirada com e sem tolerância declarada, CRL assinada por outra
  chave.
- Mutação: `invalida_retroativamente → false` derruba
  `key_compromise_invalida_o_carimbo_mesmo_tendo_sido_revogado_depois` e mais
  nenhum teste.
- `cargo clippy --workspace --all-targets -- -D warnings` — limpo.
- `production_profile_is_fail_closed` foi reescrito: fixava a mensagem antiga
  ("HTTPS … bloqueada"), e agora prova os **dois** sentidos — um perfil
  incompleto recusa em cada eixo, e um perfil completo **arranca**, que é a
  mudança desta ronda.

### Definition of Done: de 5/20 para 8/20

Passam a estar satisfeitos, além dos quatro do Marco 0: **resposta da ACT
validada**, **cliente de produção ligado ao worker**, **revogação consultada**.
Continua por satisfazer o resto, incluindo "anchors encadeados" — o
`LegalReceipt` que o `anchor()` emite continua sem campo para o digest anterior.

## MARCO 0 DA SPEC-0046 — 2026-08-30 (4)

O Marco 0 estava **inteiramente ausente**: zero ocorrências de `TrustStore`,
`X509`, `CMS` ou de um cliente HTTPS. Era o passo seguinte quando a sessão
anterior ficou sem quota, e derrubava quatro itens do DoD de uma vez.

### O que passou a existir

| § | peça | onde |
|---|---|---|
| §11 | `TrustStore` configurável, sem nomes de ACT no core | `trust_store.rs` |
| §9 | `IcpBrasilTimestampVerifier` — CMS, cadeia, EKU, imprint, nonce, política | `icp.rs` |
| §10 | `SecureTsaClient` — HTTPS, timeouts, tectos, sem redirects, mTLS opcional | `secure_tsa.rs` |
| §38 | PKI sintética para os testes | `test_pki.rs` (só `cfg(test)`) |

### A mudança que interessa

O verificador antigo tira a chave **de dentro do próprio token**
(`verify.rs:60`, `token.tsa_key`). Isso deteta corrupção e nada mais: quem
forjar um par de chaves produz um recibo que passa — e o doc-comment dizia-o,
que era o que impedia o sistema de afirmar conformidade que não tinha.

Agora a chave vem de um certificado que tem de encadear até uma âncora que o
**operador** instalou. É a diferença entre *"estes bytes não foram alterados"*
e *"uma autoridade credenciada afirmou esta hora"*.

### Decisões, e as objeções que levantaram

- **Usar `x509-cert` e `cms` em vez de escrever ASN.1 à mão.** São da família
  RustCrypto, a mesma do `der`/`spki`/`const-oid`/`p256` que o crate já usava —
  uma só versão de `der` em toda a árvore, sem duplicação de tipos. A objecção
  é real: são dependências novas num crate com gates de supply-chain (§0049).
  A alternativa era pior: um validador X.509 caseiro é a coisa mais perigosa
  que se pode acrescentar a um crate de compliance, e um que *pareça* certo é
  pior do que nenhum.
- **RSA foi acrescentado porque sem ele isto seria teatro.** Os tokens
  ICP-Brasil reais são `SHA256withRSA`. Um verificador que só fizesse ECDSA
  passaria todos os testes sintéticos e recusaria todos os carimbos de
  produção.
- **A ordem das verificações não é arbitrária.** A cadeia é validada **antes**
  da assinatura. Ao contrário gastava-se CPU a validar assinaturas de emissores
  desconhecidos e — pior — convidava ao erro de reportar "assinatura válida"
  para um token que ninguém devia aceitar.
- **O TLS confia no mesmo trust store que o carimbo, não nas raízes do
  sistema.** Se confiasse no sistema, qualquer CA pública do mundo podia emitir
  um certificado para o nome da ACT e interpor-se. Consequência assumida: com o
  trust store vazio o cliente **não liga a lado nenhum**, e nem sequer se
  constrói.
- **`http://` é recusado na construção, não no envio.** Um cliente que se deixa
  construir com um endpoint inseguro é um cliente que alguém usa por engano.
- **Redirects não se seguem, e não há como os ligar.** Seguir um redirect num
  POST binário é reenviar o digest para um destino que o servidor escolheu —
  exactamente o que a validação de certificado existe para impedir.
- **Dois signatários num token são recusados.** Qual das assinaturas sustenta a
  hora seria ambíguo, e escolher uma é pior do que recusar.
- **A validade dos certificados é aferida no instante do CARIMBO, não no de
  hoje.** Um carimbo emitido enquanto o certificado era válido continua a
  provar a hora depois de ele expirar — é a razão de existir de um carimbo.
- **Uma âncora tem de ser auto-emitida.** Aceitar um intermédio como âncora
  faria o verificador confiar num elo cuja emissão ninguém verificou, e o
  operador não veria a diferença ao olhar para a pasta.

### O que continua por fazer, e está declarado no código

- **Revogação (CRL/OCSP) não é consultada.** Um certificado revogado mas dentro
  da validade **passa**. Está em `VerifiedTimestamp::revocation_checked`, que é
  sempre `false` — no *resultado*, não só na documentação, para que quem
  construa um relatório a partir disto não possa afirmar mais do que foi feito.
- **Sem `nameConstraints` nem `policyMapping`.** A cadeia é por correspondência
  exacta de nomes em DER com verificação de `basicConstraints`. Chega para a
  topologia raiz → AC → ACT da ICP-Brasil; para uma malha com cross-certificados
  não chega, e recusa em vez de adivinhar.
- **O `SecureTsaClient` ainda não substituiu o `HttpTsa` no worker.** Trocar o
  cliente do caminho vivo é uma mudança de configuração de produção (o endpoint
  tem de passar a `https` e o trust store tem de estar povoado, senão o
  servidor deixa de arrancar a ancoragem). Fica para uma decisão do operador,
  não para um commit que a force.
- **Interoperabilidade com uma ACT real não está provada.** Os testes usam uma
  PKI sintética com a mesma estrutura; um `.tst` emitido por uma autoridade
  credenciada é evidência de laboratório e entra pela SPEC-0049.

### O que isto desbloqueia

Com `SecureTsaClient` a falar HTTPS, o `GuardedTsaClient` da soberania passa a
ser instalável: o `EgressEndpoint::validate()` exige `scheme == "https"` e o
cliente antigo só falava HTTP — eram incompatíveis por construção. A
incompatibilidade acabou; falta a decisão de trocar o cliente no worker.

### Validação

- `heraclitus-compliance`: **79 testes unitários** (era 43) + 4 de integração.
  18 no verificador ICP, 8 no trust store, 9 no cliente HTTPS.
- Cada recusa tem um teste próprio: cadeia sem âncora, assinatura de outra
  chave, `messageDigest` que não corresponde, `signedAttrs` sem `contentType`,
  carimbo sobre outro conteúdo, nonce trocado, nonce em falta, carimbo do
  futuro, certificado sem `id-kp-timeStamping`, certificado fora da validade,
  `eContentType` errado, token sem certificado, dois signatários, política
  errada, token acima do tecto, lixo em vez de DER.
- Validado por **mutação**: pôr `verificar_assinatura` a devolver sempre `Ok`
  derruba `uma_assinatura_de_outra_chave_nao_passa`.
- `cargo clippy --workspace --all-targets -- -D warnings` — limpo.


### Dois defeitos que a suíte completa expôs, e que os testes isolados escondiam

Ambos meus, ambos só visíveis com o workspace inteiro a correr.

**1. O `rustls` entrava em pânico, não devolvia erro.** A árvore tem `ring`
**e** `aws-lc-rs` (vindos de dependentes diferentes), e com os dois presentes o
`ClientConfig::builder()` não consegue escolher um provider por omissão — e
resolve isso com um `panic!`. Num servidor seria uma paragem no primeiro
carimbo, não uma falha tratável. O provider passou a ser escolhido
explicitamente. Passava em `-p heraclitus-compliance` porque a unificação de
features aí é outra; só o `--workspace` o mostrou.

**2. Um sighting duplicado por cada evento.** O mesmo `SecurityEvent` chega ao
`evaluate_threat` por dois caminhos — a derivação, e depois o próprio derivado
a passar pelo subscriber. Dois problemas somados:

- a evidência estava ancorada no LSN de **cada representação** em vez do LSN do
  episódio bruto, portanto os dois caminhos produziam identidades diferentes;
- o `DirectLogSink::append` **ignora** a chave de idempotência (só um host com
  deduplicação própria a honra), e eu confiei nela. Os sinais já tinham um
  conjunto explícito de ids emitidos; os sightings não.

Corrigido nos dois: a evidência ancora no `source_lsn` do bruto, e os sightings
deduplicam por `(indicador, tipo de match, evento)` num conjunto próprio.
Validado por mutação — remover a deduplicação derruba o teste.

**A asserção que apanhou isto estava ela própria errada.** Era um
`sleep(200ms)` seguido de "o head não mudou", que media a velocidade do worker
ao mesmo tempo que a ausência de ciclo: sob carga, um derivado ainda a caminho
contava como realimentação. Passou a esperar que o log **estabilize** e só
então exigir que fique parado — um ciclo verdadeiro nunca estabiliza — e a
contar cada tipo de derivado para provar que não há duplicados.

### Definition of Done: de 1/20 para 5/20

Passam a estar satisfeitos: **verificador RFC 3161 de produção**, **cadeia de
confiança validada**, **TrustStore configurável**, **HTTPS para ACT**. Continua
por satisfazer o resto, incluindo "anchors encadeados" — o `LegalReceipt` que o
`anchor()` de produção emite não tem campo para o digest anterior.

## VERIFICAÇÃO 2026-08-30 (3) — SPEC-0046: o que foi construído, e o que dele está ligado

Uma sessão paralela implementou os Marcos 1–4 da SPEC-0046 (≈5 500 linhas em
sete módulos novos do `heraclitus-compliance`) e ficou sem quota a meio. Esta
nota é a verificação adversarial desse trabalho **contra o código**, com nove
agentes independentes cuja tarefa foi **refutar** cada afirmação, mais três a
inventariar lacunas. Não é um resumo do que a outra sessão relatou.

### O veredicto, numa linha

O código está correcto e **quase nada dele estava ligado**. Oito das nove
afirmações vieram `PARCIAL`, todas pela mesma razão, e é a razão que esta base
já tem nome próprio para: *implementado, testado, nunca chamado*.

| garantia | corpo da função | chamador de produção |
|---|---|---|
| legal hold → HRKM → GC bloqueado | correcta, elo a elo | **não havia** |
| política versionada + replay AS OF | correcta (sem global; a versão está gravada na decisão) | não |
| pacote ANPD determinista, sem submissão automática | correcta | não |
| StrictAirGap nega antes do backend | correcta no wrapper | não |
| propagação de classificação | correcta (conjunto vazio dá o nível mais alto) | não |
| allowlist/denylist do exportador ANPD | correcta | não |
| ancoragem diferida A0→A1 | correcta | não |
| bundle offline assinado | correcta — rehash da árvore toda, não só do manifesto | não |
| honestidade sobre ICP-Brasil | **correcta e imposta** | **sim** |

A última linha é a excepção que interessa: a honestidade não é um comentário, é
estrutural. `config.validate_security()` torna `production_mode = true`
impossível de arrancar, o boot declara "não validada", e `verify_receipts` falha
fechado perante um token externo. O invariante C4/C5 aguenta.

### O que foi ligado agora

**1. A porta de entrada do legal hold (§94 / C10).** O circuito estava inteiro —
`place_legal_hold` persiste o evento *e* carimba o HRKM, o `plan_gc` respeita o
bit, o `ensure_crypto_shred_allowed` bloqueia o crypto-shred — e era
**inalcançável**: não havia rota REST, nem RPC, nem comando. Em produção o bit
`retention.legal_hold` nunca passava de `false`, portanto o ramo
`GcBlockReason::LegalHold` era código morto num servidor real.

Passou a haver três operações no RPC `admin`: `legal-hold-place` e
`legal-hold-release` com papel `Admin`, `legal-holds` com `Auditor` — ler quem
está retido não muda nada. A lógica saiu do despachante para
`grpc::legal_hold_op`, porque o que precisa de teste é o **efeito**, e testar um
braço de `match` exigiria montar um `Request` autenticado.

Duas decisões que valem por si:

- **O `created_at_lsn` é carimbado pelo servidor, não pelo pedido.** Um cliente
  que escolhesse o LSN podia datar o hold antes de uma destruição já ocorrida e
  fazer o registo mentir sobre a ordem dos factos.
- **Omitir `lsn_end` retém o que existe agora, não o futuro.** Um hold de fim
  aberto reteria eventos que nenhuma autoridade avaliou.

**2. A reconciliação que o próprio código exigia e ninguém fazia.** O
doc-comment de `reconcile_legal_holds` diz *"Call at boot and immediately before
any automated GC cycle"* — e não tinha um único chamador. O
`set_legal_hold_range` só marca os segmentos que **existem** no momento em que o
hold é colocado; um segmento selado depois disso, dentro do mesmo intervalo de
LSN, ficava sem o bit e o GC automático coletava-o. Prova sob retenção judicial
apagada, sem nada o assinalar.

A janela era teórica enquanto nada em produção conseguia colocar um hold.
Deixou de ser no momento em que o RPC passou a conseguir — por isso as duas
correcções andam juntas. Agora reconcilia-se **no arranque** (o log é a
autoridade, o HRKM é derivado, e um restauro de manifesto fá-los discordar) e
**antes de cada passagem de GC**. Uma falha na reconciliação **salta** a coleta
dessa passagem: trocar prova por espaço em disco é a troca errada.

Testes: quatro, incluindo um que percorre a operação do RPC com o corpo JSON que
um operador enviaria e verifica que o crypto-shred passa a falhar, que o GC fica
sem candidatos, e que levantar o hold devolve as duas coisas. Validados por
mutação — saltar a reconciliação derruba o teste da janela.

### O que continua por ligar, e porquê

**O guard de soberania não é instalável.** `EgressEndpoint::validate()` exige
`scheme == "https"`; o `HttpTsa` que o servidor usa em produção fala HTTP sobre
um `TcpStream` cru e **recusa** qualquer coisa que não seja `http://`. São
mutuamente exclusivos por construção. Não é wiring em falta — é o cliente HTTPS
do Marco 0, que não existe. Enquanto não existir, ligar o `GuardedTsaClient` é
impossível, e a promessa de air-gap não vale nada em runtime: o worker de
compliance faz egress com o cliente cru.

**O veto `PreventDestruction` lê decisões que nada pode escrever.** O
`ensure_crypto_shred_allowed` consulta-as, mas `evaluate_and_persist` não tem
chamador — é um gate cosmético até ter um.

**`retention.class` e `classification.rank` não têm produtor.** O gate do
crypto-shred lê estes atributos do episódio; nenhum caminho do repositório os
escreve. Ficam dependentes de um cliente externo os pôr à mão — leitura
oportunista, não enforcement. E o `classify_derived_episode` continua sem
chamador: o produtor real de derivados (`heraclitus-distill`) ignora-o.

**Sem superfície para o resto.** Dashboard, ANPD, ancoragem diferida, bundles de
modelo e soberania não têm rota REST nem subcomando. Os motores existem e não há
operador que os accione.

### Definition of Done: 19 dos 20 itens por satisfazer

O Marco 0 está **inteiramente ausente** — verifiquei por conta própria: zero
ocorrências de `TrustStore`, `X509`, `CMS` ou de um cliente HTTPS em todo o
crate. Isso derruba quatro itens do DoD directamente (verificador RFC 3161 de
produção, cadeia de confiança, trust store, HTTPS), e a ausência propaga-se:
sem validação de cadeia não há prova temporal (C6), e o `LegalReceipt` que o
`anchor()` de produção emite não tem sequer campo para o digest anterior,
portanto "anchors encadeados" é inalcançável pelo worker.

A transcrição da sessão paralela termina com *"Vou agora atacar essa fronteira
de produção"* — o Marco 0 era o passo seguinte quando a quota acabou. A
sequência estava certa; é onde recomeçar.

### O item do DoD que está satisfeito

*"Replay mantém histórico de políticas"* — e a hipótese de refutação (versão
lida de um global no momento da avaliação, o que faria o replay reproduzir a
política de hoje) **não se confirmou**: não há global nenhum, a `PolicyIdentity`
viaja dentro da `RegulatoryDecision` e o `decision_id` é um BLAKE3 sobre
(identidade da política, contexto, requisitos). C12 aguenta.

### Nota operacional: o disco encheu, e a suíte é cúmplice

Durante esta sessão o volume `D:` chegou a **0 bytes livres** — o mesmo volume
onde a base viva escreve. Duas causas:

1. `D:\cargo-target` com **352 GB**. É cache de build partilhado por toda a
   máquina (`CARGO_TARGET_DIR`), inflado por ter passado a coexistirem
   artefactos de perfis diferentes — ligar `overflow-checks` em release muda o
   hash do perfil e cria um conjunto novo sem apagar o antigo. Removidos os
   perfis `release`, `doc`, `criterion` e o alvo cruzado: 15 GB livres.
2. **897 directórios de teste abandonados** em `D:\tmp`. O `dir_teste` do
   `hrkl_v6_manifest.rs` construía `temp_dir()/hrkm-it-{pid}-{nome}` e fazia
   `remove_dir_all` **no início** — o que limpa a corrida anterior do *mesmo*
   pid, e o pid muda a cada corrida. Cada `cargo test` deixava o seu lixo.

O segundo é um defeito, não um incómodo: uma suíte que cresce sem limite acaba
por parar a máquina que a corre, e neste caso a máquina também aloja a base. O
helper passou a devolver um `tempfile::TempDir`, que se apaga no `Drop` — daí
devolver o guarda em vez do `PathBuf`: um `PathBuf` não tem como saber quando o
teste acabou. Verificado: nove testes passam e deixam **zero** directórios.
## ATUALIZAÇÃO 2026-08-30 (2) — SPEC-0047 deixou de ser código sem chamador

A auditoria nomeou o padrão desta base — *implementado, testado, nunca
chamado* — e a SPEC-0047 tinha acabado de lhe acrescentar um caso meu: o
módulo `threat` não era referenciado fora de si próprio. Deixou de ser.

`threat/plane.rs` liga as peças ao runtime:

```text
arranque   feeds_dir/*.json → StixImporter → admit (§10/§12) → IocIndex
por evento SecurityEvent → indicadores → lookup exacto → SecuritySignal
                                                       + ThreatSighting
```

Opt-in por `[sentinel.threat]`, como o L2 e o L3, e pela mesma razão: quem
ligou o L0 não deve começar a ingerir feeds externos por causa disso.

### Decisões, e as objeções

- **A extracção de indicadores é declarada, não adivinhada.** A tentação é
  varrer o `attributes` do evento à procura do que *pareça* um domínio ou um
  hash. Isso produz falsos positivos com ar de autoridade: um `user_agent` que
  contém `evil.com` não é uma ligação a `evil.com`, e um campo de 64 hex pode
  ser um id de sessão — e o analista que recebe o match não tem como saber que
  foi uma heurística a inventá-lo. Por isso a extracção sai de campos tipados
  (`src`/`dst`) e de uma lista fechada de chaves de atributo. Um indicador que
  a base observa mas não está na lista não é correlacionado: é uma lacuna
  visível (acrescenta-se a chave) em vez de um match errado.
- **Um feed malformado não impede o arranque.** Fica no `ThreatLoadReport` e
  o resto carrega. Deixar um problema de terceiros virar indisponibilidade
  nossa é a troca errada.
- **O relatório distingue "vazio porque nada importou" de "vazio porque não há
  feeds"** — e é consultável depois do arranque, não só visível no momento em
  que passou.
- **O mesmo indicador em dois campos conta uma vez.** Casar duas vezes inflaria
  o score de §11 sem evidência nova.
- **O relógio é o do evento, não o da máquina.** Um replay a um LSN antigo
  reproduz a decisão que era correcta então (§12).
- **Um `trust_level` mal escrito cai para `untrusted`.** §13: um erro de
  configuração não pode promover um feed a autoridade.
- **Um evento sem sujeito não produz sinal.** Um sinal sem sujeito não é
  accionável e só enche o incidente.
- **O nº de indicadores entra na versão do detector no checkpoint.** Dois
  checkpoints com o mesmo `pipeline_version` e índices diferentes não descrevem
  o mesmo detector, e um replay que não os distinguisse explicaria mal porque é
  que o mesmo evento deu resultados diferentes.
- **Contra-argumento que ficou por resolver:** os feeds são lidos **uma vez**,
  no arranque. Recarregar a quente é outra coisa — §40/§41 querem versionamento
  e rollback, o `ThreatFeed` existe para isso e ainda não está ligado — e fazê-lo
  mal daria dois índices a decidir ao mesmo tempo. Hoje um feed novo exige
  reiniciar o serviço.

### Validação

- 10 testes em `tests/spec0047_threat_sync.rs`, dos quais dois novos percorrem
  o runtime real: um episódio bruto entra no log e saem um `SecuritySignal` e um
  `ThreatSighting` derivados, sem ninguém chamar nada à mão. O teste verifica
  também que **nenhum** episódio de acção aparece — §11 — e que o derivado não
  se realimenta.
- 10 unitários em `threat/plane.rs`.
- `cargo test --offline --workspace` — **1030 testes, 0 falhas**; clippy
  `--workspace --all-targets -D warnings` passa.

## CORREÇÕES 2026-08-30 — os seis achados fechados, e um erro meu

### O erro primeiro: aquilo não era flakiness, era um bug de disponibilidade

Escrevi duas vezes que o `hrkl_v6_crash::sobrevive_a_kills_repetidos` era
"sensibilidade a carga" e "não regressão". **Estava errado.** O teste estava a
apanhar um defeito real, e o timing só decidia se o kill calhava na janela.

`RawSegmentWriter::create` fazia:

```rust
let mut file = OpenOptions::new().create_new(true)...open(path)?;
file.write_all(&header.encode())?;
Ok(Self { .. })          // ← sem fsync
```

O `create_new` publica a entrada no directório **imediatamente**; o `write_all`
fica em buffers do SO. Morrer nessa janela deixa um ficheiro de segmento com
zero bytes (ou meio header) no disco.

No arranque seguinte, `V6Log::open` faz `read_v6_header(path)?` sobre o
activo → `FileHeaderV6::decode` → `"short header"` → **a base recusa abrir**. Só
saía dali com alguém a apagar o ficheiro à mão. Não há perda de dados
committed — mas há perda de disponibilidade, e a recuperação exige uma pessoa
que saiba o que está a fazer.

A lição operacional é a que interessa: **um teste de segurança contra crash que
falha intermitentemente é um relatório de bug, não ruído.** Foi precisamente
por eu o ter classificado como ruído que ele sobreviveu duas auditorias.

Corrigido nos dois lados:

1. **Prevenir** — o `create` sincroniza o header e a entrada de directório
   antes de devolver. Custa um fsync por rolagem de segmento (8 MiB+), que não
   se mede.

   > **Correcção de 2026-09-03.** Este ponto afirmava que o fsync estabelece o
   > invariante *"um ficheiro de segmento que existe tem um header completo"*, e
   > que a recuperação o podia assumir. É falso, e a suposição custou caro: um
   > fsync fecha a janela contra perda de energia, **não** contra a morte do
   > processo entre duas syscalls. Um SIGKILL entre o `create_new` e o
   > `write_all` deixa na mesma um ficheiro de zero bytes. A recuperação tem de
   > filtrar o toco — é o ponto 2 que fecha o problema, não o ponto 1.
2. **Recuperar** — bases já partidas por uma build anterior voltam a abrir: um
   ficheiro activo mais curto que `FILE_HEADER_LEN` é tratado como o que é, um
   toco de crash, e removido com um aviso. Não pode conter nenhum registo
   porque os registos vêm depois do header. A condição é só o comprimento: um
   header completo com bytes errados continua a falhar alto, porque isso é
   corrupção.

Regressão em `um_segmento_activo_sem_header_nao_impede_o_arranque`, validada por
mutação. E o crash-test passou **6 de 6** corridas depois da correcção.

### Os outros cinco

| # | achado | correcção |
|---|---|---|
| 1 | o GC segurava o mutex do writer durante os `unlink` | `commit_gc` partido em `commit_gc_manifest` (sob o lock) + `unlink_gc_targets` (fora dele). A ordem crash-safe de §90 não muda — muda a fronteira do lock |
| 2 | sem `overflow-checks` em release | ligado. 328 testes em release, 0 falhas, nenhum overflow — a rede não custa correcção nenhuma hoje, e apanha a próxima verificação que faltar |
| 3 | `KeyStore::shred` prometia mais do que o meio dá | documentado o que garante (destruição da chave, §98) e o que não garante (a reescrita in-place não apaga em CoW nem em SSD com wear levelling; snapshots e réplicas ficam intactos por construção) |
| 4 | `ERASURE` era `static` de processo | passou a `Extension` do router. Dois routers no mesmo processo deixam de partilhar o flag |
| 6 | Raft invisível na suíte por omissão | o comentário que justificava o off-by-default estava obsoleto (os marcos que ele esperava aterraram em 2026-07-10); actualizado, e um teste chamado `consenso_so_e_testado_com_features_replication` torna a lacuna visível no output, já que os nomes dos testes são sempre impressos |

### Validação

- `cargo test --offline --workspace` — sem falhas.
- `cargo test --offline --release -p heraclitus-log -p heraclitus-core
  -p heraclitus-tier -p heraclitus-query` — **328 testes, 0 falhas** com
  `overflow-checks = true`.
- `hrkl_v6_crash::sobrevive_a_kills_repetidos` — **6/6**.
- Mutação: pôr `curto = false` na detecção do toco derruba a regressão nova.

## AUDITORIA DE BUGS 2026-08-30 — relatório completo

**Método:** varrimento por classe de defeito sobre `crates/*/src` e `tools/*/src`,
com leitura do contexto de cada candidato. Um "candidato" só entra abaixo depois
de eu ler o código à volta e perceber se a guarda existe. Inclui os resultados
**negativos**, porque numa auditoria saber o que foi verificado e está bem vale
tanto como a lista de defeitos.

### Achados

#### 🟠 1. O GC segura o mutex do writer durante os `remove_file`

`V6Log::collect_garbage` (código meu, desta sessão) chama `commit_gc` com o
`state` tomado. O `commit_gc` faz duas coisas: comita o HRKM **e** desliga os
ficheiros. A primeira tem de ser sob o lock; a segunda não. Como está, os
`unlink` acontecem com o mutex do writer na mão, portanto **os appends param**
durante a passagem.

Normalmente é irrelevante (uma geração RAW por segmento empacotado, microssegundos
por ficheiro). O caso que importa é o outro: **a primeira passagem num banco que
nunca correu GC** — que é a situação de todas as instalações existentes, porque
até hoje o GC não corria. Um banco com mil gerações superseded acumuladas para
appends durante a varredura inteira.

Correcção: partir o `commit_gc` em comitar-manifesto (devolve os caminhos
resolvidos) e desligar-ficheiros, e fazer o segundo depois de largar o lock. A
ordem crash-safe mantém-se — é a mesma sequência, só com a fronteira do lock
noutro sítio.

#### 🟠 2. Overflow silencioso em release, sem rede de segurança

`[profile.release]` define `lto` e `codegen-units` e **não define
`overflow-checks`**. Em release, `a - b` em `u64` dá a volta em silêncio.

Verifiquei os sítios que importam e **não encontrei nenhum explorável**: os
decoders de bloco e de rodapé chamam `check_coherence` no `decode`, e essa
função recusa `first_lsn > last_lsn`, `restart_count` que não cabe no bloco e
`uncompressed_len` acima do tecto de §140 — antes de qualquer subtracção. Os
`unwrap` em `u32::from_le_bytes(buf[a..b].try_into().unwrap())` estão todos
depois de um `if buf.len() < N { return Torn }`.

O problema não é o código de hoje, é a ausência de rede. Toda a garantia assenta
em verificações escritas à mão, uma a uma. Para um banco cujo modelo de ameaça
inclui explicitamente ficheiros adulterados (§84, §140), `overflow-checks = true`
converte um wrap silencioso num crash — que é o comportamento que se quer, porque
um crash é visível e um wrap não. Custo: alguns por cento. É decisão de produto,
mas o estado actual significa que a **próxima** verificação em falta será
silenciosa.

#### 🟡 3. `KeyStore::shred` promete mais do que o sistema de ficheiros dá

```rust
// Best-effort overwrite so the raw key bytes do not linger on disk.
if let Ok(meta) = std::fs::metadata(&path) {
    let _ = std::fs::write(&path, vec![0u8; meta.len() as usize]);
}
std::fs::remove_file(&path)?;
```

Reescrever um ficheiro no sítio **não apaga os blocos originais** num sistema
copy-on-write (ReFS, btrfs, ZFS) nem num SSD com wear levelling: o controlador
escreve noutra página e a antiga fica lá até ser reciclada.

O que a §98 exige de facto é a **destruição da chave**, e isso o `remove_file`
faz. A lacuna é entre o nome (`shred`) e a garantia: quem lê a assinatura pode
concluir que os bytes desapareceram. O comentário diz "best-effort" mas não diz
*porquê* é best-effort, que é a parte accionável.

#### 🟡 4. `ERASURE` é estado global de processo, não do router

`rest.rs:18` — `static ERASURE: AtomicBool`, escrito em
`router_with_sentinel`. Dois routers no mesmo processo (testes, ou uma segunda
instância embebida) partilham o flag: o último a ser construído decide pelos
dois. No desenho actual — um servidor por processo — não é explorável, mas é
configuração guardada fora do estado a que pertence, e é o tipo de coisa que
surpreende primeiro num teste e só depois em produção.

#### 🟡 5. e 6. Já reportados na auditoria de ontem

O flaky do `hrkl_v6_crash` sob carga, e os 18 testes de Raft que não correm nas
features por omissão (`cargo test --workspace` diz "ok" com `0 passed`).

### Verificado e **sem** defeito

Isto não é enchimento: são as hipóteses que testei e que o código refutou.

| classe | resultado |
|---|---|
| `unwrap` em decoders sobre input externo | **guardado** — todos precedidos de verificação de comprimento (`format.rs`, `block.rs`, `footer.rs`) |
| coerência de cabeçalhos v6 | **guardada** — `check_coherence` corre em cada `decode`, no bloco e no rodapé |
| ordem de aquisição de locks | **consistente** — `packing_lock`/`sidecar_lock` sempre antes de `state`, nunca ao contrário, em todos os 28 sítios |
| `block_on` dentro de async | **ausente** do caminho de produção; o deadlock de 2026-07-10 não voltou |
| erros de fsync engolidos | os três `let _ =` estão em caminhos best-effort documentados (rollback após escrita falhada; fsync de directório que é no-op em Windows) — **nenhum no caminho durável do append** |
| limite de corpo HTTP | **existe** — os únicos extractores são `Json<T>` e `Query`, e o axum 0.7 aplica o tecto de 2 MB por omissão |
| exposição por omissão | **fechada** — REST e gRPC em `127.0.0.1`, CORS vazio, `rest_allow_erasure = false` |
| bind público sem auth | **recusado na validação** — `config.rs:1016-1022` erra se o endereço não for loopback sem auth, e sem TLS no gRPC |
| `unimplemented!()` / `todo!()` / `#[ignore]` | **zero** em todo o workspace |
| `prune_old_manifests` vs. commit concorrente | **seguro** — protege explicitamente a geração corrente e só remove abaixo do `keep` |

### Leitura geral

O código defende-se bem contra a classe de erro que mais o ameaça — input
corrompido ou adulterado. Cada decoder valida antes de indexar, e as validações
estão escritas nos dois sentidos (a política decide, e um invariante separado
volta a verificar). Os dois achados com peso não são erros de lógica: um é uma
fronteira de lock que eu próprio pus no sítio errado ontem, e o outro é uma
opção de compilação em falta que hoje não custa nada e amanhã custa a primeira
verificação esquecida.

## AUDITORIA 2026-08-29 (3) — o estado real, verificado contra o código

**Método:** o mesmo que este ficheiro exige de si próprio — cada afirmação
verificada por leitura/grep sobre `crates/*/src` e `tools/*/src`, e pela suíte
de testes executada. `graphify-out/` excluído. Nada aqui vem de ler os
documentos.

### O que está genuinamente feito

| crate / ferramenta | LOC (src) | LOC (tests) | testes |
|---|---|---|---|
| `heraclitus-log` (HRKL v6) | 19 787 | 4 458 | 192 unit + 15 suítes |
| `heraclitus-sentinel` | 16 544 | 486 | 156 unit + 12 integração |
| `heraclitus-server` | 8 400 | 108 | 33 |
| `heraclitus-qualifier` | 8 444 | — | 71 |
| `heraclitus-query` | 6 299 | 323 | 44 + 10 |
| `heraclitus-tier` | 5 810 | 1 183 | 68 unit + 18 integração |
| `heraclitus-core` | 4 479 | — | 55 |
| `heraclitus-raft` | 3 099 | — | 18 (só com `--features replication`) |
| `heraclitus-compliance` | 1 716 | 151 | 18 + 4 |

`cargo test --offline --workspace` — **996 testes, 0 falhas** (features por
omissão). Dois factos que valem a pena registar porque são raros:

- **zero `unimplemented!()`, zero `todo!()`, zero `#[ignore]`** em todo o
  workspace. Não há "implementado" que seja um `panic!` à espera.
- os módulos novos vêm com testes de mutação, não só com testes que passam.

### O achado principal: o GC do HRKL v6 nunca corre

`plan_gc` e `commit_gc` **não têm um único chamador de produção**. Só testes e
comentários. Verificado três vezes, por caminhos diferentes:

1. `grep -rn "plan_gc\|commit_gc"` fora de `src/v6/gc.rs` e de `tests/` devolve
   apenas linhas de documentação;
2. o servidor tem sete tasks de fundo (checkpoint, telemetria, packing v6, HRKI,
   lakehouse, compaction do tier v1, distill) e **nenhuma** é de GC;
3. não existe `v6_gc_interval_secs` na `HeraclitusConfig`, nem subcomando de GC
   na CLI (`inspect`, `verify`, `prove`, `storage`, `manifest`, `migrate-v6`,
   `export`, `migrate-encrypt`, `verify-receipts` — mais nenhum).

**O custo é mensurável e é hoje.** O `record_pack` marca a geração RAW como
`Superseded` (§88 passo 13) e nada a remove: o único `remove_file` no caminho do
motor apaga um segmento activo *vazio*. Com o rácio `packed/raw` de **21,95%**
medido no gate de §207 em 2026-08-24, um banco fica com `1,00 + 0,2195 = 1,22`
do tamanho RAW em vez de `0,22` — **5,5× mais disco** do que o formato promete,
para sempre, em todos os segmentos.

E, com o GC parado, ficam inertes com ele: o grace period de §93, os pins de
§92, o legal hold de §94, a política de cópias de §184, o `assert_gc_invariant`
de §91 e o `cold_detached` corrigido nesta mesma sessão. É um andar inteiro de
política a que nada chama.

O trabalho para ligar é pequeno face ao que destranca: uma task de fundo com um
intervalo configurável, um subcomando de CLI para o operador correr à mão, e o
`GcExecution` a sair na telemetria. O `plan_gc` já explica cada bloqueio, o
`commit_gc` já é crash-safe e já está testado com injecção de crash
(`hrkl_v6_gc_crash.rs`).

### O padrão, e o inventário completo dele

O `SPEC-RESUMO.md` já lhe deu nome duas vezes ("9 testes a passar e **zero
chamadores**"). Vale ter a lista toda num sítio, ordenada por custo:

| o que | estado | custo hoje |
|---|---|---|
| GC v6 (`plan_gc`/`commit_gc`) | sem chamador | **5,5× disco**; toda a política de §90–§97 inerte |
| `repack_generation` / `collect_cold_locations` | sem chamador | nenhum ainda; depende da catalogação no HRKM |
| `threat::*` (SPEC-0047) | sem consumidor | nenhum feed é ingerido; nenhum `SecurityEvent` é correlacionado contra o `IocIndex` |
| projecção lakehouse | `interval = 0` por omissão | nenhum — é deliberado e documentado (§99: duplicaria o disco sem pedir licença) |
| compaction do tier v1 | `interval = 0` e inerte em v6 | nenhum — o boot di-lo |
| `hume-ir`, `hume-sketches` | zero consumidores | nenhum — declarado no `Cargo.toml` como infra da SPEC-0043 |

As três últimas linhas são escolhas registadas. As três primeiras não são: são
código completo à espera de uma linha de wiring.

### Achados sobre a própria suíte de testes

**1. `hrkl_v6_crash::sobrevive_a_kills_repetidos_a_meio_do_append` é flaky sob
carga.** Falhou **2 de ~6** corridas de `--workspace` e passou **4 de 4** em
isolamento. A causa é estrutural, não aleatória: o teste faz `cargo build` dentro
de si e mata um processo filho numa janela de tempo fixa
(`sleep(25 + (i*11)%90)` ms). Sob a carga de um `--workspace` — que é
exactamente o que o CI corre — a janela desloca-se e o filho morre antes de
escrever o que o teste espera.

Isto é pior do que um teste que falha: é um **teste de segurança contra crash**
que grita falsamente. É o alarme que toda a gente aprende a ignorar, e no dia em
que apanhar uma regressão a sério ninguém vai olhar. A correcção é fazer o filho
sinalizar prontidão (um ficheiro, uma linha em stdout) em vez de se confiar num
`sleep`.

**2. Os 18 testes de consenso não correm nas features por omissão.**
`cargo test --workspace` devolve `heraclitus_raft: 0 passed`. O CI corre
`--all-features` e apanha-os, mas um programador que corra a suíte localmente
fica sem cobertura nenhuma de Raft **e sem saber disso** — o resultado diz "ok",
não "0 testes".

### Números que os documentos tinham desactualizados

Medidos agora, com features por omissão: `heraclitus-query` **44** (o resumo
dizia 53), `heraclitus-qualifier` **71** (dizia 68), `heraclitus-server` **33**
(dizia 31). Nenhuma discrepância é uma regressão — são contagens tiradas com
conjuntos de features diferentes e nunca refrescadas. A tabela acima passa a ser
a referência, e diz com que features foi medida.

### O que está bloqueado em coisas de fora, e está certo assim

- **SPEC-0049** — os gates `GovernmentProduction` exigem atestações
  independentes de laboratório (carga, falhas, red-team, DR, PDU/hipervisor,
  assinatura). A suíte recusa-se a auto-certificá-las e devolve exit 2. Correcto.
- **SPEC-0046** — `StrictAirGap` não existe no crate (zero ocorrências) e a
  cadeia ICP-Brasil está declaradamente por validar, com o dizê-lo escrito no
  próprio código (`receipt.rs:16`, `verify.rs:41`, `tsa.rs:117`, `signer.rs:211`).
- **SPEC-0051** — travada pelo seu §14; falta só a qualificação externa da 0049
  e a decisão sobre `SKIP_VALUES`.

### Recomendação, por ordem

1. **Ligar o GC do v6.** É o único achado com custo de produção **hoje**, o
   código já existe e já está testado com injecção de crash, e o trabalho é uma
   task + um knob + um subcomando. Nada mais nesta lista tem esta relação entre
   esforço e efeito.
2. **Corrigir o flaky do `hrkl_v6_crash`.** Barato, e protege a credibilidade da
   única suíte que testa perda de dados.
3. **Fazer o `heraclitus-raft` correr na suíte por omissão**, ou fazer a suíte
   dizer em voz alta que não o está a correr. "0 passed" a reportar "ok" é a
   forma mais silenciosa de perder cobertura.
4. **SPEC-0046** (em curso).
5. **SPEC-0048** — é a última SPEC completamente vazia.
6. Catalogação de gerações frias no HRKM, e o consumidor do plano de threat
   intel — os dois são "ligar o que já existe", como o GC, mas sem custo a
   correr contra eles hoje.

## ATUALIZAÇÃO 2026-08-29 (2) — SPEC-0047 Threat-Sync: Marcos 0, 1 e 4 implementados

A SPEC-0047 não tinha uma linha de código: o alvo `heraclitus-sentinel::threat`
não existia. Passa a existir, com o IR canónico, os índices exatos, a camada de
confiança, o importador STIX 2.1, o versionamento de feed e o sanitizador —
`crates/heraclitus-sentinel/src/threat/` (9 módulos).

### O que foi feito, por § da spec

| § | área | módulo |
|---|---|---|
| §4–§6, §9, §12 | IR canónico, proveniência, ciclo de vida | `threat/ir.rs` |
| §21 | canonicalização antes de indexar | `threat/canonical.rs` |
| §22–§23 | TLP 2.0 e propagação | `threat/tlp.rs` |
| §7 | índices exatos; Bloom só como prefilter | `threat/index.rs` |
| §10–§13 | trust da fonte, gate de admissão, IOC→sinal | `threat/trust.rs` |
| §36–§37 | sightings | `threat/sighting.rs` |
| §40–§41 | versionamento e rollback de feed | `threat/feed.rs` |
| §24–§27 | sharing policy, pseudonimização, gate de fuga | `threat/sharing.rs` |
| §14–§17 | import STIX 2.1 com limites de entrada | `threat/stix.rs` |

Cobre os Marcos 0 (IR + índices + proveniência), 1 (importer STIX) e 4 (TLP +
sanitização + sharing policy).

### Os invariantes são tipos, não comentários

O padrão que organiza o módulo: onde a spec diz "nunca", o código não oferece a
operação.

- **T3 — «Bloom match != confirmed IOC match».** `prefilter()` devolve
  `PrefilterHit`, que é opaco: sem campos, sem métodos, sem conversão para
  `ConfirmedMatch`. O único produtor de `ConfirmedMatch` é `lookup()`, que
  consulta a estrutura exata. Não há atalho para remover à pressa — que é
  exatamente quando este atalho costuma ser tomado.
- **T8 — sanitização antes de exportar.** `SanitizedThreatObject` tem um campo
  privado, portanto só o sanitizador o constrói. Qualquer superfície de export
  que o aceite está garantidamente a receber conteúdo sanitizado.
- **T5 — provenance obrigatória.** `ThreatProvenance` é campo, não `Option`.
- **T4 — intel sozinha nunca autoriza resposta.** Reutiliza (não duplica) o
  `correlation::high_impact_allowed`, que exige ≥2 detectores independentes e
  pelo menos um canal `Rule`/`Graph`. Há teste aqui porque uma garantia que vive
  noutro módulo desaparece silenciosamente num refactor.
- **T6 — ciclo de vida.** Um objeto sem `valid_until` e cuja fonte não declara
  TTL é **recusado** no gate.

### Decisões, e as objeções que levantaram

- **IDNA não é aproximado — é recusado.** §21 pede normalização IDNA. Fazê-la a
  sério é UTS-46 + tabela Unicode + verificações bidi, e o crate não tem (nem
  deve ter) essa dependência. Meia implementação mapearia alguns domínios e
  estragaria outros — e os estragados ficariam *guardados* estragados, sem nunca
  casar com o tráfego que deviam apanhar. Um domínio não-ASCII devolve
  `CanonicalError::IdnaUnsupported`; punycode (`xn--…`) é ASCII e passa.
- **A canonicalização de URL é conservadora de propósito.** Normaliza esquema,
  host e porto default. **Não** normaliza caixa do path, percent-encoding,
  barra final nem ordem de query — cada um desses pares é dois recursos
  diferentes, e fundi-los é a alteração semântica que o §21 proíbe. É uma
  promessa mais estreita do que a de um normalizador de URL típico, e é a que a
  spec pede.
- **O subset de STIX patterning é declarado, não silencioso.** Implementar uma
  fração da linguagem e tratar o resto como "sem indicadores" produz um
  importador que reporta sucesso e ingere nada. O importador aceita comparações
  de igualdade sobre paths conhecidos e reporta o resto como
  `PatternSupport::{Partial, Unsupported}`, contado no `ImportReport`. O padrão
  original é preservado para reexport (§17).
- **Distinguir «não percebemos» de «o feed está mal».** Um path suportado com
  valor inválido (`ipv4-addr:value = '999.1.1.1'`) entra em
  `rejected_values`, não em `unsupported_patterns`. A primeira falha é nossa; a
  segunda é do feed.
- **`confidence` ausente é 50, não 100.** O STIX torna-o opcional. Ausente é
  "não declarado", e o valor neutro é o meio da escala.
- **TLP ausente ou ilegível é RED.** O default do enum é `Red`, e um
  `object_marking_refs` que não resolve contribui `Red`. É o único default cujo
  modo de falha é uma divulgação.
- **O TTL ancora no `valid_from` da fonte, não na hora do download.** Ancorar em
  `now` daria a um indicador de há seis anos uma vida nova a cada re-sync — §12
  derrotado por um ciclo de refetch.
- **Um match de sufixo/prefixo pesa metade de um exato.** Casar
  `a.b.evil.com` contra `evil.com` é uma afirmação mais fraca do que casar
  `evil.com`; pontuá-los igual é como um indicador largo passa a dominar uma
  avaliação. O `MatchKind` viaja no match, no sinal e no sighting.
- **Fontes untrusted pesam exatamente zero, e um match delas não gera sinal
  nenhum** — não «um sinal com score 0». A mera presença de um sinal é lida como
  significando algo por uma vista de incidente ou um dashboard.
- **Hashes fuzzy (SSDEEP/TLSH) nunca entram no índice exato.** São digests de
  *similaridade*: dois ficheiros diferentes partilham prefixo com frequência, e
  tratar isso como identidade é produzir falsos positivos confiantes (T2). O
  `insert_object` devolve quantos indicadores indexou, para que a diferença seja
  visível em vez de silenciosa.
- **A pseudonimização é `HMAC(chave_por_destino, id)`,** com `blake3::keyed_hash`.
  Um hash simples de um identificador previsível está a uma wordlist de
  distância do plaintext; e chaves diferentes por destino impedem que dois
  destinatários cruzem pseudónimos e reconstruam o nosso inventário. O `Debug`
  do `Pseudonymizer` imprime `<redacted>` — uma chave logada uma vez quebra o
  esquema retroactivamente.
- **Objeção resolvida a meio:** o `rollback_to` desativava apenas as versões
  *posteriores* ao alvo. Libertar uma quarentena e depois ativar essa versão
  deixava duas versões `Active` ao mesmo tempo, e o `active()` respondia com a
  primeira do vetor. Passou a desativar todas as outras não-quarentenadas —
  duas versões em vigor não é um estado que o tipo deva conseguir representar.

### O que NÃO foi feito, e porquê

Não são omissões por falta de tempo; cada uma precisa de algo que este crate não
tem e não deve ter:

- **Cliente e servidor TAXII (§18, §19).** O `heraclitus-sentinel` não tem
  cliente HTTP, TLS nem runtime assíncrono, e adquiri-los aqui punha uma stack
  de rede no plano de derivação. A fronteira `ThreatImporter` é a costura onde
  um transporte encaixa: um cliente TAXII é um ciclo de fetch a alimentá-la, e
  pertence ao servidor.
- **Adaptador MISP (§20).** Mesma razão, mais o §1, que proíbe explicitamente
  fixar a versão do formato — sem fixtures de uma instância real o adaptador não
  prova nada.
- **Transporte CTIR (§28–§32).** O §30 diz que a `HttpApi` "NÃO será presumida"
  e a orientação atual é notificação institucional. Escrever um cliente contra
  uma API que ninguém publicou é inventar um protocolo.
- **Bundles air-gap (§33–§35).** Sobrepõe-se ao trabalho de evidência/air-gap da
  SPEC-0046 que está em curso; duas implementações independentes de "verificar
  um bundle assinado" divergiriam, e a que divergisse seria a menos exercitada.
- **Dashboard (§42).** Precisa das views do servidor.

Consequência honesta: os gates **T1 (TAXII)**, **T2 (MISP)**, **T6 (air-gap)** e
**T7 (CTIR)** da §43 continuam por abrir. **T0, T3, T4 e T5** estão cobertos por
testes com esses nomes.

### Validação

- `cargo test --offline --workspace` — **996 testes, 0 falhas**.
- `heraclitus-sentinel`: **156 unitários** (92 no `threat`) + 4 adversariais +
  **8 de integração** em `tests/spec0047_threat_sync.rs`, que percorrem o
  pipeline inteiro: bundle STIX → import → admissão → índice → match → sinal →
  sighting → sanitização → export.
- `cargo clippy --offline -p heraclitus-sentinel --all-targets -- -D warnings` —
  passou.
- Validados por **mutação**: (1) fazer um hit de Bloom virar match derruba
  `a_saturated_bloom_still_confirms_nothing`; (2) desligar o gate de fuga do §27
  derruba `credentials_block_the_export_regardless_of_who_proposed_them`; (3)
  fazer `may_share_to` devolver sempre `true` derruba três testes de TLP.

## ATUALIZAÇÃO 2026-08-29 — compaction do tier frio em v6: o que a spec manda não é o que faltava

O item nº 1 da "Ordem de execução atual" do `SPEC-RESUMO.md` dizia:

> Compaction do cold tier para recibos v2 — a única funcionalidade que o legado
> tem e o v6 não.

**A primeira metade da frase estava errada, e vale a pena dizer porquê antes de
dizer o que foi feito.** O que o legado tem é o
`ColdTier::compact_cold(… is_deleted …)`: recebe um predicado, reescreve o
segmento **sem** os registos marcados e recomputa a raiz Merkle. Portar isso
para recibos v2 seria implementar exactamente o que a SPEC-0050 proíbe:

- **§96** — uma operação equivalente a `compact_cold(… is_deleted …)` que
  produza um `.hrkl` omitindo records "NÃO poderá ser tratada como nova
  representação canônica equivalente"; é *projection compaction*.
- **§97** — se `input CanonicalRecords != output CanonicalRecords` então as
  raízes lógicas diferem e o output **não substitui** o segmento canónico.
- **§95** — delete semântico é um evento *tombstone*, não a remoção do registo.
- **§98** — o que torna dado pessoal irrecuperável é crypto-shredding (chave
  destruída, evento preservado), e é do `heraclitus-compliance`.

E o modo de falha seria caro: o recibo v2 produzido seria internamente
consistente, verificaria, e o problema só apareceria quando alguém tentasse
provar um LSN que já lá não estava — possivelmente meses depois, numa perícia.

O que **realmente** faltava no v6 é o ciclo de vida das gerações frias: repack
(§189/§190), recolha física no bucket, e o GC do log a saber que uma `location`
pode não ser um caminho local.

### O que foi feito

| entrega | onde |
|---|---|
| `ColdTierV6::repack_generation` — repack de geração fria preservando a raiz | `tier/src/compaction.rs` |
| `ColdTierV6::collect_cold_locations` — remoção física idempotente no bucket | `tier/src/compaction.rs` |
| `GcExecution::cold_detached` + separação local/remoto no `commit_gc` | `log/src/v6/gc.rs` |
| `OBJECT_STORE_GENERATION_PREFIX` / `is_object_store_location` | `core/src/runtime.rs` |

### Um bug latente que isto fecha

`PhysicalGeneration::location` tanto pode ser `segments/…` como
`canonical/<ns>/segment-…/generation-N.hrkl` (§82) — o próprio comentário do
campo já dizia "caminho local **ou** chave de object storage". O `commit_gc`
mandava as duas para `resolve_gc_path`, que canonicaliza o directório-pai
contra a raiz local. Para uma chave de bucket esse directório não existe: o `?`
devolvia `Err` **antes** do commit do manifesto.

Consequência prática: bastava **uma** geração fria ficar superseded para o GC do
banco inteiro parar — incluindo o das gerações locais, que nada tinham a ver com
o object store. Está reproduzido em
`geracao_em_object_storage_e_desligada_mas_nao_apagada_pelo_gc`
(`log/tests/hrkl_v6_manifest.rs`) e validado por mutação: com
`is_object_store_location` a devolver sempre `false`, o teste falha com
`Err(NotFound)` no `commit_gc`, que é exactamente o sintoma descrito.

É um bug **latente**: arma-se no momento em que alguém catalogar gerações frias
no HRKM. Hoje ninguém o faz — ver "o que continua a faltar", abaixo.

### Decisões, e as objeções que levantaram

- **Autenticar antes de repackar.** Os bytes descarregados são conferidos contra
  o `physical_digest` do recibo (§84) *antes* de qualquer repack. Sem essa
  paragem, um objecto corrompido no bucket seria relido, reempacotado e
  publicado como geração nova com recibo próprio e consistente — a corrupção
  ganharia uma certidão de nascimento limpa, e a geração de origem, ainda
  correcta noutra réplica, ficaria marcada como superseded por ela. O CRC de
  bloco apanha *alguns* casos (a mutação prova-o), mas cobre payloads de bloco,
  não o ficheiro todo.
- **O `.hrki` da origem nunca é herdado.** O sidecar indexa blocos por offset
  (§56) e um repack com outro `block_target_bytes` muda todos os offsets. Um
  sidecar herdado devolveria os blocos errados **em silêncio**, porque a raiz
  lógica continuaria a bater. Publicar sem sidecar é o correcto: §56 manda
  reconstruí-lo, e o recall por intervalo de LSN usa o directório de blocos do
  próprio segmento.
- **`collect_cold_locations` não decide nada.** Pins, grace period, legal hold e
  o invariante de §91 são do `plan_gc`. O que ela garante sozinha é que só toca
  em chaves que fazem `GenerationKey::parse` — um `location` corrompido no
  manifesto não vira um `DELETE` arbitrário no bucket.
- **`saved_bytes()` devolve `i64`, não `u64`.** Repackar de `Archive` para
  `Fast` faz o objecto crescer, e é uma troca legítima quando o que se quer é
  latência de leitura. Um `saturating_sub` reportaria "0 poupados" para um
  objecto que engordou 30%.
- **Contra-argumento que ficou por resolver:** publicar uma geração fria **não a
  cataloga no HRKM**. Não existe `record_cold_generation`, e escolher como
  catalogá-la é uma decisão de modelo, não de código:
  1. a cópia fria é uma geração **nova** (N+1) com a mesma raiz lógica — cabe no
     formato actual, mas gasta um número de geração por movimento de tier e faz
     o `physical_digest` deixar de ser único entre gerações;
  2. a cópia fria é outra `location` da **mesma** geração — é o que o conceito
     pede, mas `PhysicalGeneration::location` é uma `String` só, portanto
     implica mudar o formato do `.hrkm`.

  Fica sinalizado em vez de silenciosamente escolhido, pela mesma razão do
  `cumulative_watermark`: mexe no significado de bytes já em disco.

### O que continua a faltar

1. **O wiring do repack e da recolha.** *Correcção a uma versão anterior desta
   nota, que dizia que o `ColdTierV6` não tinha chamador nenhum no caminho vivo:
   tem.* `Engine::demote` publica a geração e appenda o recibo v2,
   `verify_demotion_v2` verifica-a e `recall` lê-a por intervalos
   (`server/src/engine.rs`). O que **não** tem chamador é o par novo —
   `repack_generation` e `collect_cold_locations` — e isso depende da decisão de
   catalogação acima: sem gerações frias no HRKM não há `plan_gc` que decida
   coletá-las.
2. **A geração fria vive no log, não no catálogo.** O recibo v2 entra no log
   como episódio, mas nada chama um `record_cold_generation` (que não existe)
   para a pôr no `.hrkm`. Consequências concretas: os estados de §72
   (`Active`/`Verified`/`Superseded`) não se aplicam a uma cópia fria, o
   `plan_gc` nunca a vê, e o defeito de localidade corrigido acima permanece
   latente em vez de activo.
3. **§175 (compactação lakehouse)** — que, à luz de §96, é o nome certo para "a
   compaction que o legado tinha": *projection compaction*. O `compact_cold` do
   v1 e o §175 resolvem o mesmo problema em camadas diferentes; a diferença é
   que o §175 opera sobre a projecção, regenerável por definição (§100), e não
   sobre o histórico canónico.
4. **Recuperar espaço de tombstones no HRKL** — não é dívida, é proibido (§95).
   Quem quiser dado irrecuperável usa crypto-shredding (§98).

### Validação

- `cargo test --offline --workspace` — **896 testes, 0 falhas**.
- `heraclitus-tier`: 68 unitários + 5 (repack frio) + 6 (Fase 5) + 7 (Fase 6).
- `heraclitus-log --test hrkl_v6_manifest`: 9 testes, incluindo o novo.
- `cargo clippy --offline -p heraclitus-tier -p heraclitus-log -p heraclitus-core
  --all-targets -- -D warnings` — passou.
- Validados por **mutação**: `is_object_store_location → false` derruba o teste
  do GC com `Err(NotFound)`; desligar a conferência de `physical_digest` derruba
  o teste do objecto adulterado (o erro deixa de nomear a causa).
- Nota de flakiness, sem relação com esta mudança:
  `hrkl_v6_crash::sobrevive_a_kills_repetidos_a_meio_do_append` falhou uma vez
  numa corrida de workspace e passou em quatro corridas seguintes. O teste faz
  `cargo build` dentro de si e mata um processo filho por janela de tempo
  (`sleep(25 + (i*11)%90)` ms); sob a carga de um `--workspace` a janela
  desloca-se. É sensibilidade a carga, não regressão — nenhum caminho tocado
  aqui entra no append RAW, na reparação de cauda ou no rodapé.

## ATUALIZAÇÃO 2026-08-29 — SPEC-0049 validada; SPEC-0045 v1 fechada

Esta nota acrescenta o estado verificado nesta auditoria ao relatório histórico
acima. O aviso de que a pasta contém RFCs continua válido para as specs que não
foram implementadas; não deve ser lido como prova de que nenhuma peça posterior
foi construída.

### SPEC-0049 — suíte de qualificação

`tools/heraclitus-qualifier` agora implementa planos Q1–Q6, workload
determinístico, execução de carga/corrupção/restore, evidências seladas,
verificação, SBOM, supply-chain e modo air-gap. Os harnesses, runbooks e
workflows de CI estão em `qa/`, `docs/qualification/` e `.github/workflows/`.

Validação local: `cargo test --offline --workspace --all-features --locked`
terminou com **0 falhas**, incluindo os 19 testes do qualifier. A suíte pode
produzir evidência de desenvolvimento verificável, mas o perfil
`GovernmentProduction` permanece **Unqualified** até receber as atestações
externas assinadas exigidas pelo plano (carga, falhas, red-team, DR,
PDU/hipervisor e assinatura).

## ATUALIZAÇÃO 2026-08-29 — SPEC-0049: Definition of Done (§143) fechada

Os 35 itens da §143 passaram a estar implementados. O detalhe item a item está
em [SPEC-RESUMO.md](SPEC-RESUMO.md); aqui fica o que muda na leitura do estado.

**O que a nota de 2026-08-27 dizia e já não é verdade.** Faltavam a suíte de
soak, o crash-loop contra o processo de release, o runner da matriz Raft, o
gate de zero-egress, o histórico de qualificação, o compromisso criptográfico
que liga o relatório ao binário, o workflow de release de emergência, os onze
runbooks da §117, o doctor de configuração e a comparação de regressão. Todos
existem, com testes: o `heraclitus-qualifier` passou de 19 para **68 testes**.

**O que continua Unqualified, e porquê isso está certo.** Power-loss físico,
perda de host, red team independente, soak de 168 h, DR, air-gap e runbooks
validados por terceiros exigem laboratório e infraestrutura. A suíte recusa-se
a auto-certificá-los — §35 e §110 mandam-nos vir de fora, e §107 garante que
`Skipped` e `Inconclusive` nunca contam como `Passed`. Correr o plano
governamental hoje devolve exit code 2, que é o resultado correto.

### Quatro correções que a implementação forçou, e que valem por si

1. **`source_digest` incluía ficheiros não versionados** (`git ls-files
   --others`). Um clone do commit só traz os versionados, por isso o digest era
   irreprodutível por qualquer terceiro — exatamente o contrário do que a §111
   exige. Efeito secundário medido nesta árvore: 48 635 ficheiros não
   versionados contra 1 640 versionados, e a suíte de testes do qualifier
   ficava **mais de 28 minutos pendurada** a hashear uma pasta de build. Passou
   a 38 s. O estado não versionado deixou de entrar no hash e passou a ser
   reportado em `untracked_files`, virando limitação declarada acima de
   Development. A afirmação anterior de que a suíte corria com 0 falhas
   continua verdadeira, mas corria por 28 minutos por esta razão.

2. **`percentil` em `crates/heraclitus-analytics/benches/hume_vs_datafusion.rs`**
   falhava `cargo clippy --workspace --all-targets --all-features -- -D
   warnings`. Como esse comando **é** o gate `lint` de todos os planos, ele
   reprovava antes de qualquer outro gate correr. Corrigido (`&mut Vec` →
   `&mut [_]`); o clippy do workspace passa agora com `-D warnings`.

3. **Variáveis de ambiente da máquina sobrepõem-se ao ficheiro de
   configuração — e apontavam para a base de dados VIVA.** Descoberto ao correr
   o `crash-loop` pela primeira vez contra um servidor real nesta máquina:
   `HeraclitusConfig::load` aplica os overrides `HERACLITUS_*` **depois** do
   ficheiro, e o ambiente de máquina aqui tem `HERACLITUS_DATA_DIR =
   D:\HeraclitusDB\data` e `HERACLITUS_GRPC_ADDR = 127.0.0.1:7474`. Sem
   tratamento, um ensaio de crash teria arrancado um servidor sobre os dados de
   produção e matado o processo à martelada — e a evidência teria registado a
   configuração que o harness escreveu, não a que correu, o que a §7 e a §9
   proíbem. O que salvou foi o `AddrInUse` do porto já ocupado pelo serviço.
   O supervisor passa a limpar **todas** as variáveis `HERACLITUS_*` do
   ambiente do filho e a listá-las no relatório (`neutralised_environment`).
   Vale para além do qualifier: qualquer ferramenta que passe um ficheiro de
   configuração ao servidor nesta máquina está sujeita ao mesmo efeito.

4. **O próprio soak tinha uma fuga de memória.** O registo de latências
   acumulava toda a amostra da execução; num soak de 168 h a alguns milhares de
   operações por segundo isso são milhares de milhões de amostras. O detetor de
   fugas cresceria sem limite e reprovaria a execução que estava a medir. Passou
   a usar um reservatório determinístico com decimação (teto de 262 144
   amostras, sem RNG, para a §111 continuar a valer), e o relatório declara
   quando os percentis globais são amostrados. Os percentis **por janela** —
   que são os que mostram deriva — continuam exatos.

### Limites que o código declara nos próprios relatórios

Não estão só na documentação; estão nos artefactos, para que ninguém os
descubra tarde:

- `crash-loop` grava `power_loss_equivalent: false` e a razão (§25: a page
  cache do SO sobrevive ao `kill -9`);
- `egress-monitor` grava que a amostragem prova egress mas **não** a ausência
  dele, e que a ausência é do tap de rede independente (§98);
- o soak marca `Inconclusive` — nunca `Passed` — quando o host não consegue ler
  alguma série de recursos (PQ17);
- o crash-loop grava `neutralised_environment` com as variáveis que removeu do
  ambiente do servidor.

### Execução real, não só testes unitários

O Q2 foi corrido ponta a ponta contra o binário do servidor: **3 ciclos, 203
appends confirmados, 3 mortes abruptas, 0 ausentes após reabrir**, verificação
de integridade OK em cada reinício e re-leitura **individual** de todos os 203
(escopo `full`, não amostrado). `head` após o reinício ficou em 72, 131 e 206
para 71, 58 e 74 confirmados — a progressão que a §24 exige.

### SPEC-0045 — Sentinel

A fundação da Fase 0 existe em `crates/heraclitus-sentinel`: configuração
desabilitável, `SecuritySubscriber` não bloqueante, fila limitada com catch-up
por LSN, cursor persistido, normalização genérica determinística, proteção
contra reprocessamento de eventos derivados, `SecurityEvent` com proveniência,
métricas e integração opcional ao servidor legado/v6. A Fase 1 agora inclui um
frontend Sigma restrito e fail-closed, carregamento determinístico de regras,
integração L1 ao replay do runtime e persistência idempotente de
`SecuritySignal`. A Fase 2 acrescenta o `BehavioralEngine` com adaptador runtime
determinístico: eventos canónicos viram features escalares limitadas por
entidade, com EWMA/Welford/quantis, score robusto, perfis shadow, promoção
explícita, quarentena, rate limiting e snapshots AS-OF de replay; eventos
suspeitos e evidência L1 ficam fora do baseline salvo feedback confiável
explícito.

Fase 3 agora também fornece um grafo temporal de segurança com AS-OF/path
determinístico, `IncidentEngine` com agrupamento/transições e `EvidenceFusion`
versionada com guarda de independência. O adaptador L3 é opt-in por
`[sentinel.l3]`: o worker projeta `SecurityEvent` no grafo, consome
`SecuritySignal` live/replay e persiste revisões append-only de
`SecurityIncident` com identidade BLAKE3 e parents causais. O worker também
funde sinais L1/L2 em revisões versionadas de `SecurityRiskAssessment`. O boot
reconstrói o estado em ordem de LSN de transação; as APIs internas oferecem
filtro, incidente AS-OF, grafo AS-OF e baseline comportamental AS-OF. Testes
rebobinam o cursor e confirmam que eventos/sinais/riscos/incidentes não duplicam.
Derivados do servidor passam por `Engine` e os
namespaces/tipos Sentinel são reservados contra forja externa. Em configuração
Raft, todas as réplicas podem manter L0–L3, mas apenas o epoch do líder pode
executar L4, aprovações ou respostas. A Fase 4 agora invoca um `ModelBackend`
fornecido pelo host, valida e persiste `SecurityInvestigation`; a Fase 5
persiste propostas, decisões e `SecurityApproval` append-only. A Fase 6 mantém
epoch/lease, identidade idempotente e circuit breaker ligado ao caminho L4, e inclui um
`MemoryReversibleExecutor` seguro para integração, além do `DryRunExecutor`.
Atualizações de modelo/ruleset e feedback humano são agora eventos de
governança versionados e append-only; feedback não altera diretamente modelo,
baseline ou policy. As métricas P0–L4/ações estão expostas no status.
O servidor expõe views REST (incidentes, evidência, WHY, ações, aprovar/negar,
dashboard e checkpoint) e equivalentes gRPC administrativos com RBAC. O DoD
v1 da §115 está fechado no código e nos testes. Credenciais/adaptadores reais
para IAM/firewall/Kubernetes e atestações laboratoriais pertencem ao
host/ambiente por §51–52 e §114; por isso `autonomous` continua rejeitado
fail-closed até receber evidência e executor qualificados.

O gate P0 passou em três execuções consecutivas do benchmark final, usando
`FsyncPolicy::Always`, seis rondas de 1.000 appends e ordem baseline/subscriber
alternada. As medianas observadas foram `-1,38%`, `1,21%` e `-21,97%`; todas
ficaram abaixo do limite normativo de `3%`. O benchmark falha o processo quando
a mediana ultrapassa o limite e mede apenas o trabalho alcançável antes do ACK
(broadcast, atomics e `try_send`); processamento L0–L4 e appends derivados são
assíncronos e ficam fora do caminho crítico por arquitetura.

## ATUALIZAÇÃO 2026-08-24 (4) — HRKL v6 é o banco. Nenhuma capability recusa arrancar.

`storage_format` passou a ter **`v6` por omissão**. E, mais importante do que a
troca do default: as três capabilities que falhavam fechadas em v6 deixaram de
falhar.

### Raft em v6 — a afirmação de que estava acoplado ao layout legado era falsa

Este documento (e o meu próprio resumo da sessão anterior) dizia que "a state
machine, os snapshots e o `install_snapshot` do openraft assentam no modelo
físico legado". **Não assentam.** Verificado por grep sobre o crate inteiro: em
`consensus.rs`, `grpc.rs`, `net.rs` e `lib.rs`, os únicos métodos do log usados
são `append_replicated`, `head` e `scan` — os três já no `EpisodeLog`. O
acoplamento era uma assinatura de tipo (`Arc<Log>`), não uma dependência real.

Trocado por `Arc<AnyLog>`. A suíte de consenso passou a correr contra os dois
formatos, escolhidos por ambiente:

```bash
cargo test -p heraclitus-raft --features replication                            # v6 (default)
HERACLITUS_RAFT_TEST_FORMAT=legacy cargo test -p heraclitus-raft --features replication
```

**18 testes passam nos dois.** Eleição, quórum, failover, transferência de
snapshot, raft-log durável com restart de processo, transporte TCP e gRPC — tudo
sobre HRKL v6.

### Compliance em v6 — já tinha saído na actualização (2)

### Cold tier v1 em v6 — recusa substituída por aviso

A compaction v1 percorre recibos de demote **v1**; num banco v6 todos os
recibos são v2, portanto a task nunca encontra o que compactar. Recusar o
arranque do servidor inteiro por causa de uma task de fundo opcional era
desproporcionado; deixá-la a girar em silêncio seria pior, porque o operador
ligou-a à espera de que algo acontecesse. Agora o servidor arranca, a task **não
é iniciada**, e o boot diz porquê:

```
Compaction do cold tier  INERTE em v6: percorre recibos v1 e o v6 emite v2; a task não é iniciada
```

### O que um operador vê ao actualizar sem migrar

Os dois layouts continuam isolados nos dois sentidos — o v6 nunca converte dados
implicitamente. Mas o erro deixou de ser um beco:

```
esta pasta contém um log v1--v5 (00000000000000000000.hrkl), e o HRKL v6 nunca
converte dados implicitamente.

Duas saídas:
  1. migrar (a origem NÃO é alterada):
       heraclitus migrate-v6 <origem> <destino-novo>
     e depois apontar `data_dir` ao destino;
  2. continuar no formato antigo:
       storage_format = "legacy"   (ou HERACLITUS_STORAGE_FORMAT=legacy)
```

### A prova de que as peças funcionam juntas

`cluster_v6_replica_empacota_e_ancora_ao_mesmo_tempo`: três nós na configuração
**por omissão** (v6 + Raft por TCP), 60 escritas pelo consenso, replicação e
indexação nos três, ancoragem de compliance, packing dos segmentos, e o recibo
**continua a verificar depois do packing** — a propriedade que a raiz lógica dá
e a raiz física legada não dava. O cluster continua a aceitar escritas no fim.

O teste tem um `assert` explícito de que o default é v6: se alguém o reverter,
o teste passa a exercitar o legado, e falha em vez de o fazer em silêncio.

### O que ficou de fora, e é honesto dizer

- **Compaction do cold tier para recibos v2** não existe. A v1 é inerte em v6, e
  o aviso di-lo. Implementá-la é trabalho a sério, não um adaptador.
- **Projecção lakehouse continua opt-in** (`v6_lakehouse_interval_secs = 0`).
  Packing e HRKI são compressão e índices — poupam espaço, e por isso estão
  ligados por omissão. O lakehouse é uma **cópia** dos dados noutro formato;
  ligá-la por omissão duplicaria o disco de toda a gente sem pedir licença.
- Os dois testes do demote/compaction **v1** passaram a fixar
  `storage_format = Legacy` explicitamente. Herdar o default novo faria testes
  do caminho legado a exercitar o v6 — passariam a testar outra coisa.

### Validação

- `cargo test --offline --workspace` — **742 testes, 0 falhas**, agora com v6
  como formato por omissão de toda a suíte.
- `heraclitus-server` com `tier,analytics,distill,replication` — 46 testes.
- `heraclitus-raft --features replication` — 18 testes em v6 **e** 18 em legado.
- Clippy `-D warnings` limpo em core, log, raft, tier, cli, compliance, sim e
  server com todas as features.

## ATUALIZAÇÃO 2026-08-24 (3) — migração v1–v5 → v6: o v6 passa a ser adoptável

Terceira ocorrência do mesmo padrão nesta spec, e a mais consequente: o
`v6::migrate` tinha 9 testes a passar, tratava cada versão do formato, o
`opaque_meta` e a cauda rasgada — e **zero chamadores**. Não havia driver de
base completa nem comando. Tudo o que as Fases 0–6 construíram estava
inalcançável para qualquer instalação que já tivesse dados.

Agora existe `migrate_database()` e `heraclitus migrate-v6 <origem> <destino>`.
Garantias mecânicas: a origem fica byte a byte intacta (§133), o destino tem de
não existir (§83), a identidade v6 é recomputada e nunca herdada (§131), a
contiguidade de LSN é verificada e um buraco é erro duro (§5), e a cauda activa
sai selada (§130). Cada segmento deixa um `LegacyMigrationReceipt` **persistido**
— até agora o tipo existia mas só em memória, e uma ponte auditável que não
sobrevive ao processo não é auditável.

Uma cauda rasgada **recusa** migrar em vez de migrar metade: §130 manda
"recover according to legacy rules", mas essa recuperação trunca o registo
parcial e violaria a promessa de não tocar na origem.

**Inconsistência pré-existente encontrada e sinalizada, não corrigida:** o
backend legado grava `cumulative_watermark = head` (último LSN + 1) e o v6 grava
`= max_lsn`. Não causa bug hoje, mas o `EpisodeLog::manifest()` é agora genérico
sobre os dois. Corrigir mexe no significado de bytes já no header do `.hrkm`,
portanto fica registado em vez de alterado às escondidas.

Validação: 742 testes no workspace, 0 falhas; 6 de integração da migração (sobre
uma base escrita pelo `Log` de produção, não bytes fabricados) e 1 no CLI a
percorrer o ciclo do operador; Clippy `-D warnings` limpo. Mutações deliberadas
derrubam os testes respectivos.

**O v6 continua a NÃO ser o default.** `storage_format` é `legacy` por omissão, e
virar isso é decisão de produto: uma instalação que actualize o binário sem
migrar veria o motor recusar abrir a sua base — as raízes são isoladas nos dois
sentidos, de propósito. O caminho existe; a decisão não foi tomada.

## ATUALIZAÇÃO 2026-08-24 (2) — SPEC-0050 Fase 6 fechada; compliance sai do v6

A Fase 6 (lakehouse) estava numa situação particular que vale a pena nomear,
porque é um modo de falha que se repete em projetos grandes: **as duas pontas
existiam e estavam testadas, e não havia corda entre elas.**

- o `heraclitus-log` sabia registar uma projecção Parquet no HRKM
  (`attach_parquet`) e recalcular o watermark contíguo de §104 — com testes;
- o `heraclitus-tier` sabia materializar Parquet v2, metadata Iceberg v2 real
  e commits Delta — com 34 testes unitários;
- **nada chamava o segundo a partir do primeiro.**

A consequência mensurável: `parquet_export_lag_lsn` era exposto em `/metrics` e
crescia para sempre, porque media um pipeline que nunca corria. Um número que
parecia saúde e era ficção.

### O que foi feito

| peça | onde |
|---|---|
| fronteira no log: `V6Log::lakehouse_pending()` + `attach_parquet_projection()` | `log/src/v6/engine.rs` |
| trabalhador que atravessa a fronteira | `tier/src/lakehouse/worker.rs` |
| task de background no servidor + config (`v6_lakehouse_*`) | `server/src/lib.rs`, `core/src/config.rs` |
| `heraclitus export` e `heraclitus manifest show` (§120) | `cli/` |
| doctor vê projecções obsoletas (`STALE_PARQUET_PROJECTION`) | `log/src/v6/doctor.rs` |

O trabalhador vive no `heraclitus-tier` pela mesma razão da Fase 5: o
`heraclitus-log` não conhece `object_store` nem `async`, e não passou a
conhecer. O log expõe a fronteira; o tier atravessa-a. O CLI e o servidor
conduzem **o mesmo** trabalhador — duas implementações do mesmo export
divergiriam, e a que divergisse seria a do caminho menos exercitado.

### Um bug latente que a Fase 6 teria activado

§176 diz que "Parquet superseded pode ser coletado **segundo regras do
lakehouse**". O `commit_gc` não fazia essa distinção: resolvia o `location` de
qualquer artefacto derivado como caminho local e chamava `remove_file`. Com um
Parquet num object store isso ou **falhava** a canonicalizar a URI (bloqueando
o GC inteiro), ou não encontrava nada e reportava `removed` para um objecto que
continuava vivo no bucket. Enquanto ninguém chamava `attach_parquet`, era
inofensivo; ligar a Fase 6 tornava-o real.

Corrigido: o `.hrki` é local e o GC apaga-o; o Parquet é desligado do manifesto
e reportado em `GcExecution::lakehouse_detached` como dívida da outra camada.
Reportar a dívida é honesto; fingir a remoção não é. Teste:
`parquet_obsoleto_e_desligado_do_hrkm_mas_nao_apagado_pelo_gc` — falha com o
código antigo.

### Compliance deixou de ser recusado em v6 — e ficou melhor

O servidor recusava arrancar com `storage_format = "v6"` e ancoragem ligada.
A recusa era honesta mas desnecessária: o compromisso é uma Merkle sobre as
raízes dos segmentos selados, e **ambos** os backends as publicam no
`DatabaseManifest`. O `commit_at` passou a ler do manifesto em vez do `Log`
concreto — sem adaptador que fabrique `SegmentMeta` legado a partir de v6, que
é exactamente o que §69 proíbe.

O que muda não é cosmético:

| | raiz do segmento | sobrevive a repack? |
|---|---|---|
| v1–v5 | Merkle **física** dos bytes do ficheiro | **não** |
| HRKL v6 | raiz **lógica** canónica (§7.2) | **sim** |

Sob o esquema legado, empacotar um segmento invalida um recibo já notarizado:
os bytes mudam, a raiz muda, e a reverificação acusa "log alterado
retroativamente" sobre uma história intacta. Sob v6 isso não acontece — provado
por `um_repack_nao_invalida_um_recibo_ja_emitido`. Os dois domínios têm
separadores distintos no imprint (`COMMIT_DOMAIN` vs `COMMIT_DOMAIN_V6`) para
que um verificador não possa aplicar o errado e reportar fraude onde não há; o
recibo passou a gravar qual usou, com um default **nomeado** para que um recibo
anterior ao v6 se releia como `legacy-physical` — um `#[serde(default)]` simples
daria a string vazia e obrigaria o verificador a adivinhar o que "" significa
(`um_recibo_sem_dominio_le_se_como_legado`).

### O que continua por fazer, e porquê

- **Fase 7 (`PackedEpisodeV1`)** — §204 condiciona-a: *"Somente após benchmarks
  demonstrarem benefício além de Zstd."* A pré-condição é uma medição, e a
  medição foi feita: o Zstd `Balanced` deixa **21.95%** dos bytes RAW num corpus
  operacional real (comprime 4.56×), com §153 e §155 também a passar. **O gate
  não abre** — um codec estruturado com dicionários disputaria essa quinta parte
  ao preço de um encoding físico novo em disco, de um ciclo de vida de
  dicionários (§45) e da sua colisão com a cifra por `agent_id` (§47). Números,
  ressalvas e o que reabriria a decisão em
  [`resultados/SPEC-0050-fase7-GATE.md`](resultados/SPEC-0050-fase7-GATE.md).
- **Fase 8 (indexação avançada)** — §205 declara-a **"Opcional"**.
- **Raft em v6** — continua recusado no boot. Ao contrário do compliance, não
  é um problema de leitura do manifesto: a state machine, os snapshots e o
  `install_snapshot` do openraft assentam no modelo físico legado. §184 coloca
  explicitamente a política de durabilidade de réplicas "na camada de
  replication/storage durability", fora desta spec. Fica como dívida declarada
  e falha fechada, não como suporte parcial silencioso.

### Validação

- `cargo test --offline --workspace` — **742 testes, 0 falhas**.
- Gates de performance de §207 medidos, não assumidos: §153 PASS (v6 não
  regride; mediana de 5 corridas A/B alternadas), §154 PASS (`packed/raw` =
  21.95%, limite 50%), §155 PASS (fallback RAW, expansão 0).
- `heraclitus-server` com a feature `tier` — 39 testes, 0 falhas.
- Clippy `-D warnings` limpo em `heraclitus-log` (**incluindo `--all-targets`**,
  fechando os avisos dos benchmarks `carga_real_1m`/`carga_real_20m` que o
  SPEC-RESUMO listava como pendentes), `heraclitus-tier`, `heraclitus-core`,
  `heraclitus-compliance`, `heraclitus-cli`, `heraclitus-views`,
  `heraclitus-retrieval` e `heraclitus-server`.
- Os testes novos foram verificados por **mutação deliberada**: tornar
  `attach_parquet_projection` um no-op derruba 3 dos 7 testes da Fase 6; fazer
  o exportador perder 1 em cada 7 linhas derruba 6 dos 7; remover o filtro do
  GC derruba o teste de §176. Um teste que passa na presença do bug que diz
  cobrir não é cobertura.
- Corrigidos de passagem dois testes que **não compilavam** em
  `heraclitus-retrieval` e `heraclitus-views` (referências a `Log` deixadas
  para trás na migração para `EpisodeLog`/`AnyLog`). O workspace não passava
  `cargo check --all-targets` antes desta sessão.

## ATUALIZAÇÃO 2026-08-24 — SPEC-0050 ligada ao data plane do servidor

> **Nota de 2026-08-24 (2):** a Fase 6 foi fechada depois de esta secção ser
> escrita; ver a actualização no topo. O texto abaixo fica como está para
> preservar o registo do que se sabia nesse momento.

A SPEC-0050 continua **parcial** (Fases 6–8 permanecem abertas), mas deixou de
ser apenas uma biblioteca isolada. O caminho vivo agora seleciona o formato de
forma explícita:

- `storage_format = "v6"` no TOML ou `HERACLITUS_STORAGE_FORMAT=v6` abre
  `V6Log`; o default continua `legacy`.
- `EpisodeLog` + `AnyLog` desacoplam Engine, views, H-VM, query, retrieval e
  analytics do tipo concreto `Log`.
- Append, leitura, scan, tail, consulta GQL, verificação operacional e restart
  foram testados através do `Engine` em v6.
- Layout legado e v6 recusam abrir a raiz um do outro antes de qualquer escrita;
  não existe detecção permissiva nem migração implícita.
- Skip-scan continua disponível no legado; v6 usa scan conservador até a HRKI
  entrar no planner, sem risco de falsos negativos.
- Compliance, Raft e cold-tier v1 ainda dependem do modelo físico legado e são
  recusados em v6. Isso é uma lacuna declarada, não suporte parcial silencioso.
  **(Desactualizado em 2026-08-24: o compliance passou a correr em v6 — ver a
  actualização no topo deste ficheiro. Raft e cold-tier v1 continuam recusados.)**

Validação desta integração: 31 testes do servidor, 181 testes unitários mais
suítes de integração/crash do log, 53 testes do query e Clippy `-D warnings`
nos crates alterados.

## ATUALIZAÇÃO 2026-07-09 — SPEC-009-035 implementados (módulos reais)

A pedido, os SPEC-009 a 035 foram **implementados como módulos Rust reais, que
compilam e passam testes** (workspace: 206 → **254 testes, 0 falhas**), adaptados
aos tipos reais do código (`Lsn`/`SegmentId` são `u64`, não newtypes; nada do
código v3.2.0 verbatim, que não compilava).

> **Distinção honesta:** "✅ módulo" = tipo/trait/lógica implementados **e
> testados** em unidade. **Wired = ❌** significa que o módulo existe e funciona,
> mas **ainda não está ligado ao caminho vivo** (planner/servidor/gRPC) — isso é
> trabalho de integração, não de implementação. Nenhum destes é "engine de
> produção completo"; são o **contrato + implementação de referência** que os
> specs descrevem.

| SPEC | Módulo real | Testado | Wired ao motor vivo |
|---|---|---|---|
| 009 | `core::canonical::CanonicalKeyCodec` · `index_graph::dense_map` | ✅ | ✅ **completo**: codec no `index-attr` (bug −0.0/+0.0 corrigido) + `DenseEntityMap` é agora o mapa denso interno do `GraphIndex` |
| 010 | `zone_map::ZoneMap` (lsn/ts/agent/session/attrs) + `skip_scan::SkipScanner` (+ sidecar `.zmap`) + pushdown GQL `scan_builtin_eq` | ✅ | ✅ **ponta-a-ponta**: query `WHERE agent_id/session_id=…` → planner → skip por zone map → sidecar persistente (cold-boot). Salta segmentos, nunca perde match. |
| 011 | `core::runtime` (StorageEngine, DatabaseManifest, DerivedExecutionArtifact, budgets) · `txn::SnapshotManager` | ✅ | ✅ `Log::manifest()` produz o `DatabaseManifest` real (segmentos+watermark, Merkle nos selados); `StorageEngine` trait fica p/ backend alternativo. **(P3, 2026-07-16:** `txn::SnapshotManager` e `DerivedExecutionArtifact` são **referência** — `heraclitus-txn` é órfão e `DerivedExecutionArtifact` tem 0 callers; ver 019 + `../DECISAO-P3-isolation-txn.md`.**)** |
| 012/013 | `core::ir` · `core::cost` · **`analytics::vectorized`** (motor Arrow real) | ✅ | ❌ **REFERÊNCIA (decisão P1, 2026-07-16)**: `SelectivityOptimizer`→`VecExecutor` existe e passa testes (Gate C), mas **nenhum handler o invoca** e `heraclitus-analytics` é `optional`/off-by-default. A via de agregação **ligada** passou a ser o `LogAnalytics` (DataFusion) em `POST /sql` — não duplica o DataFusion (I4). Ver [`../DECISAO-P1-motor-analitico.md`](../DECISAO-P1-motor-analitico.md). |
| 014 | `index_graph::provenance::ProvenanceEngine` · `core::dispatcher` · query `WHY(…) UNTIL "cause"` (minimal chain) | ✅ | ✅ **WHY UNTIL wired na GQL** (gramática→AST→plan→backend); minimal causal chain, shortest path testado. **(Correção 2026-07-16:** o caminho vivo do `WHY` é `trace_causes` sobre o mapa `parents` do `GraphIndex` (`query/backend.rs:1632`), **não** o `ProvenanceEngine` — este tem 0 callers fora do próprio ficheiro (**referência**). O `dispatcher`/`ReplaySink` idem — ver 024.**)** |
| 016 | `core::flight` · `analytics::flight` (IPC) · **`server::flight_grpc` (protocolo REAL)** | ✅ | 🟡 **PARTIAL (correção 2026-07-16; antes dizia "COMPLETO")**: servidor `arrow.flight.protocol` real (arrow-flight 58 + tonic 0.14, listener próprio `flight_addr`) — **`FlightClient` oficial testado ponta-a-ponta** (DoGet 2500 linhas, `as_of`, GetSchema, erro limpo) + data plane IPC + rota REST. MAS é opt-in atrás da feature `analytics` (**off por default**) e os restantes RPCs (`Handshake`/`ListFlights`/`GetFlightInfo`/`PollFlightInfo`/`DoPut`/`DoAction`/`ListActions`/`DoExchange`) devolvem `Unimplemented` (`flight_grpc.rs:99-146`). |
| 019 | `core::consistency::IsolationLevel` | ✅ | 🟢 **capacidade ligada / enum de REFERÊNCIA (correção P3, 2026-07-16)**: o `AS OF` (≡ `HistoricalSnapshot`) está ligado ponta-a-ponta pelo `as_of: Option<Lsn>` de todos os métodos do `QueryBackend` (resolvido do GQL `AS OF LSN|SNAPSHOT`). O enum `IsolationLevel` + `TxnManager::begin_with` **NÃO** estão no caminho vivo (`heraclitus-txn` é órfão); os níveis não-Historical degeneram no log single-writer. Ver [`../DECISAO-P3-isolation-txn.md`](../DECISAO-P3-isolation-txn.md). |
| 022 | `core::streaming::StreamSubscriber` | ✅ | ✅ **wired**: `log::subscribe::attach_subscriber` liga ao `tail_subscribe` real (on_append por evento; overflow → catch-up LSN) |
| 023 | **HQL — REJEITADO por design** (mantém GQL) | — | — |
| 024 | `core::contracts` (Planner/Optimizer/TaskScheduler/SegmentCatalog) | ✅ | ✅ **os 6 contratos com impl viva**: `StorageEngine`+`SegmentCatalog` no `Log` real, `Optimizer`/`TaskScheduler` no motor vetorizado (012/013), `ReplaySink` no dispatcher, e agora **`Planner` = `analytics::planner::AnalyticalPlanner`** (query string → `LogicalPlan`). `run_analytical` corre Planner→Optimizer→Executor ponta-a-ponta a partir de texto (Gate C testado). **Nota P1 (2026-07-16):** o trio Planner/Optimizer/TaskScheduler vive no motor vetorizado de **referência** (não ligado — ver 012/013 e [`../DECISAO-P1-motor-analitico.md`](../DECISAO-P1-motor-analitico.md)). **(Correção 2026-07-16 — a frase antiga "os contratos de storage estão no caminho vivo" era falsa:** `SegmentCatalog` tem impl real no `Log` (`log/lib.rs:1316`) mas só é invocado por teste de integração (`log/tests/manifest.rs`); `StorageEngine` **não** tem impl no `Log` — só o `MemStore` local de teste (fica p/ backend alternativo, ver 011); `ReplaySink`/`dispatcher` têm 0 callers fora do teste do próprio módulo = **referência**.**)** |
| 025 | `core::plugin` (HeraclitusPlugin + PluginHost) | ✅ | ❌ **REFERÊNCIA (correção P4, 2026-07-16)**: `heraclitus-wasm` é órfão e o `PluginHost` só **cataloga nomes** de operadores — **nada** no query/executor **invoca** um operador `wasm:<nome>`. Ligar plugins = feature real (superfície GQL p/ UDF + dispatch no executor + ABI a sério, não o `(i64,i64)->i64` de brinquedo) + decisão I2 (o próprio `plugin.rs` admite a tensão). Ver [`../DECISAO-P4-plugins-wasm.md`](../DECISAO-P4-plugins-wasm.md). |
| 026 | `core::capability::CapabilityCatalog` (detect real) | ✅ | ❌ **REFERÊNCIA (correção P1/P4, 2026-07-16)**: o único consumidor é o `VecExecutor`, que é **referência** (nenhum handler o invoca — ver 012/013). O catálogo não é consultado no caminho vivo. |
| 027 | `EventKind::SystemMetric` · `core::telemetry` | ✅ | ✅ **wired**: `Engine::emit_telemetry` + task periódica no server (`telemetry_interval_secs`, opt-in); self-query GQL testado |
| 028/031 | `core::artifact_registry` (registry + evicção em cascata) | ✅ | ✅ **wired**: `LogBackend` mantém um `SkipScanner` persistente; cada zone map é catalogado (fingerprint/segmento) e a evicção LRU do registry despeja o cache do scanner |
| 029 | `core::format_version::StorageFormatVersion` (negociação) | ✅ | ✅ **wired**: o decode do header do segmento negoceia via SPEC-029 (major novo = rejeição dura); bytes no disco intocados; `v2_compat` verde |
| 030 | `index_graph::GraphIndex::state_hash` + trait `View` | ✅ | ✅ |
| 032 | `core::cost::EmaCalibrator` | ✅ | ✅ **wired**: o `LogBackend` mede cada skip-scan e, se o EMA disser que é >20% mais lento que o window-scan, o planner cai de volta (adaptativo, testado nos dois sentidos) |
| 033 | `core::numa` (política) + **pinning real (`core_affinity`)** | ✅ | ❌ **REFERÊNCIA (correção P1/P4, 2026-07-16)**: `pin_workers` vive no `VecExecutor` (referência, não ligado — ver 012/013) e `core::numa` tem 0 callers externos. Nenhuma thread do caminho vivo é pinned por aqui. |
| 034 | `core::ebr::Versioned<T>` (reclamação por Arc) | ✅ | ✅ **satisfeito por equivalente superior**: o `SnapshotBundle` do backend já faz blue-green via `ArcSwap` (lock-free no load); `Versioned<T>` fica como utilitário p/ novos usos |
| 035 | `core::sandbox::run_sandboxed` · **`heraclitus-wasm` (wasmtime 31)** | ✅ | 🟡 **sandbox real EM UNIDADE / NÃO ligada (correção P4, 2026-07-16)**: o isolamento WASM (memória, fuel metering, traps contidos, módulo inválido rejeitado) é real e testado no crate, MAS `heraclitus-wasm` é órfão e `run_sandboxed` tem **0 callers** — nada no caminho vivo o alcança. Ver [`../DECISAO-P4-plugins-wasm.md`](../DECISAO-P4-plugins-wasm.md). |
| 015/021 | `raft` log-shipping v0 + hardening **+ consenso openraft real (feature `replication`)** | ✅ | 🟡→✅ **consenso provado in-process** (`raft::consensus`, openraft 0.9.24): eleição+aplicação idêntica+`state_hash` bit-idêntico, **failover** (líder morto → maioria elege → writes continuam → heal → convergência), minoria isolada não faz falso ack + reintegra limpa, redirect `ForwardToLeader`, duplo failover, snapshot (round-trip **e transferência real**: líder purga o log → seguidor atrasado apanha via `install_snapshot`), **raft-log DURÁVEL em disco (`FileRaftLog`) com restart de processo provado (sem duplicar/perder), e transporte de rede TCP real (`net`: eleição/replicação/failover sobre sockets)**. Só bytes de episódios viajam (`AppData` = bincode do `Episode`). Endurecido por revisão adversarial (corrigido 1 bug real de TOCTOU no `build_snapshot`). **Wrapper gRPC/tonic FEITO (2026-07-16, P2):** `heraclitus-raft::grpc` (serviço `RaftTransport` + `GrpcNetworkFactory`) sobre os mesmos tipos serde; o servidor escolhe TCP ou gRPC via `ReplicationConfig.transport` (default `tcp`). Testado: cluster elege+replica por gRPC (raft) e 3 servidores replicam+indexam por gRPC (server). |
| 020 | crash recovery (torn-write) — **já existia** no log | ✅ | ✅ |

**Próximo nível (o que realmente falta):** o *wiring* dos módulos ao caminho vivo
está **feito** (ver coluna "Wired" — a maioria ✅; este parágrafo antigo dizia o
contrário e ficou desatualizado). O que genuinamente resta é de outra ordem de
grandeza e está deliberadamente adiado:

- **SPEC-015/021 — consenso Raft real** — **fechado em 2026-07-10** (ver linha
  015/021 da tabela): openraft 0.9 atrás da feature `replication`, com eleição,
  quórum, failover e **raft-log durável + restart de processo** provados por
  testes de cluster in-process (30× sem flake), endurecidos por revisão
  adversarial multi-agente. Corre também sobre **transporte de rede TCP real**
  (não só o router in-process) **e agora sobre gRPC/tonic** (`heraclitus-raft::grpc`,
  toggle `ReplicationConfig.transport`, feito 2026-07-16 no P2 — testado). O wrapper
  gRPC deixou de ser o passo cosmético pendente.
- **Itens "referência, não produção" já com impl real mas a endurecer:** NUMA
  node-local pleno (multi-socket; hoje só pinning round-robin), kernels AVX
  explícitos (hoje os kernels Arrow já são SIMD por baixo), quórum distribuído.

## ATUALIZAÇÃO 2026-07-10 — SPEC-024 fechado (o 6.º contrato: `Planner`)

Dos seis contratos de subsistema da SPEC-024, cinco já tinham impl viva; faltava
o **`Planner`** (query string → `LogicalPlan`, o front-end do Compiler 1).
Implementado como `heraclitus-analytics::planner::AnalyticalPlanner` — uma
gramática analítica mínima (`SELECT [WHERE …] [GROUP BY … [SUM …]]`) sobre o
schema `events`, **sem inventar linguagem de grafo** (invariante #4: GQL continua
a única linguagem da superfície de grafo/temporal). `run_analytical` liga
Planner (024) → `SelectivityOptimizer` (012) → `VecExecutor` (013) ponta-a-ponta a
partir de texto. +5 testes (parsing, erros sem pânico, e2e vs força bruta, Gate C
a partir de string). Workspace continua verde.

## ATUALIZAÇÃO 2026-07-10 — SPEC-015/021 fechado (consenso Raft real)

`heraclitus-raft` ganha `consensus` (openraft 0.9.24) atrás da feature
`replication`, cumprindo a promessa antiga do header do crate: **eleição de
líder + commit por quórum + failover automático**. Peças: `MemRaftLog` (raft-log
em memória), `EpisodeStateMachine` (apply = `append_replicated` no log local,
LSN denso), `Router` in-process com links cortáveis. Tese SPEC-015 preservada:
só bytes de `Episode` (bincode) viajam; cada nó hidrata as suas views localmente.

**Endurecido por revisão adversarial multi-agente** (4 dimensões; 2 completaram
antes do limite de sessão e produziram 8 findings — verificados à mão contra o
source real do openraft). Achado principal, **bug real** que os testes verdes
escondiam: `build_snapshot` (que o openraft corre *spawnado em paralelo* com o
`apply`) lia o log e o `applied` sem lock comum ⇒ par rasgado. Corrigido com um
lock de consistência partilhado. Também: `no_quorum` reescrito (o antigo tinha
uma cauda vácua com claim falso), `wait_leader` simplificado (era código morto),
e +3 testes novos (redirect `ForwardToLeader`, duplo failover, round-trip de
snapshot). 6 testes de cluster, 30× sem flake; workspace verde.

## ATUALIZAÇÃO 2026-07-10 — raft-log durável + restart de processo

Fechada a maior lacuna de produção do consenso: **durabilidade**.
- `crate::durable::FileRaftLog` — raft-log durável (WAL append-only com
  `Insert`/`Truncate`/`Purge`, `fsync` ANTES do ack de quórum, meta atómica para
  voto/committed, cauda torn descartada no `open`). O voto durável é a garantia
  anti-split-brain (um nó reiniciado não vota duas vezes no mesmo termo).
- `EpisodeStateMachine::open_durable` — recupera `applied`/membership de um
  sidecar e usa `skip_normals = head − normals` para NÃO re-aplicar (duplicar) os
  episódios que já estavam em disco quando o openraft re-envia
  `[applied+1, committed)` no arranque. Ordem de escrita: episódios primeiro
  (fsync), meta depois ⇒ o meta nunca fica à frente (nunca se perde um episódio).
- Teste `durable_node_survives_restart_without_dup_or_loss`: um nó durável
  encerra, reabre do disco, re-lidera com o voto durável, mantém `head`
  inalterado (sem dup/perda) e continua a comitar. +4 testes (3 de `FileRaftLog`
  + 1 e2e). 15 testes com a feature, 30× sem flake; workspace verde.

## ATUALIZAÇÃO 2026-07-10 — transporte de rede TCP real

`crate::net` — o consenso deixa de viver só no router in-process e passa a
correr sobre **sockets TCP reais**. `serve()` liga um servidor TCP por nó que
despacha RPCs (`AppendEntries`/`Vote`/`InstallSnapshot`, enquadrados por
comprimento + bincode) para o `Raft` local; `TcpNetworkFactory`/`TcpConnection`
implementam o `RaftNetwork` do openraft ligando ao `BasicNode.addr` que viaja na
membership. `spawn_node_tcp` liga um listener efémero e serve.

2 testes de integração (portas efémeras em `127.0.0.1`): (1) 3 nós elegem líder
e replicam 20 writes com os 3 logs byte-equivalentes — tudo pela rede; (2)
**failover sobre TCP**: o líder morre (`raft.shutdown()`), os 2 sobreviventes
elegem novo líder pela rede e continuam a comitar. Honestidade: é TCP puro, não
gRPC literal — um wrapper tonic sobre os mesmos tipos serde é o passo cosmético
que resta. 18 testes com a feature, 25× sem flake; clippy limpo; workspace verde.

## ATUALIZAÇÃO 2026-07-10 — consenso LIGADO ao servidor (o wiring final)

O consenso deixa de ser um módulo testado à parte e passa a ser um **modo do
`heraclitus-server`** (feature `replication` + `config.replication`):
- **Config**: `ReplicationConfig` em `heraclitus-core` (`node_id`, `raft_addr`,
  `peers`, `bootstrap`, `raft_dir`, `sm_dir`) — TOML retrocompatível
  (`replication` ausente = nó único, o caminho normal, intocado).
- **`server::cluster`**: arranca o nó de cluster sobre o log do `Engine`
  (raft-log durável `FileRaftLog` + transporte TCP + state machine durável) com
  um **hook de apply** que indexa cada episódio replicado nas views locais
  (`Engine::index_applied`, `Weak` p/ evitar ciclo) — read-your-writes
  preservado em TODOS os nós.
- **`Engine::append` roteia pelo consenso** quando ativo: o líder submete via
  `client_write` (ack só por quórum); um não-líder devolve erro com hint do
  líder. O caminho de nó único não muda uma linha de comportamento.
- **`heraclitus-raft`** ganhou a API de alto nível (`submit_episode`,
  `initialize_cluster`, `node_status`, `production_config`,
  `spawn_node_tcp_on`) e o hook `with_apply_hook` (dispara só em appends
  genuínos, nunca nas re-aplicações de restart).

Teste de integração `three_server_cluster_replicates_writes_and_indexes`:
3 servidores in-process (portas efémeras) formam o cluster, 8 escritas passam
pelo `Engine::append` do líder, os 3 nós replicam o log **e a query GQL devolve
os dados em todos** (a prova de indexação); um seguidor recusa a escrita com
hint; `state()` expõe papel/líder. 23 testes no server com a feature; suites
raft (21) e default intocadas.

**Endurecido por revisão adversarial multi-agente** (o wiring novo tinha 3
defeitos reais que testes verdes + clippy esconderam):
- **telemetria contornava o consenso** — `emit_telemetry` fazia `log.append`
  direto ⇒ com replicação divergiria/derrubaria o nó (o `append_replicated` do
  raft colide, `CasConflict`). Corrigido: passa por `Engine::append`.
- **deadlock no handler `query`** — GQL escreve (`CREATE`/`DECIDE` → `append`) e
  a auditoria também; sem `spawn_blocking`, N queries-escrita concorrentes
  parqueavam todos os workers do tokio à espera do quórum e o `RaftCore` não
  podia ser escalonado ⇒ deadlock. Corrigido (`spawn_blocking` no `append` E no
  `query`).
- **`install_snapshot` não indexava** — appendava ao log mas não disparava o
  hook ⇒ um nó que apanhava via snapshot tinha os episódios no log mas não nas
  views (queries erradas até ao boot). Corrigido: o hook dispara nos episódios
  recém-instalados; +asserção no teste de snapshot.

## ATUALIZAÇÃO 2026-07-10 — endurecimento pré-merge (revisão adversarial)

Antes de consolidar, uma revisão adversarial multi-agente dos módulos novos
(`durable`/`net`/`planner`) encontrou **5 defeitos reais** que testes verdes +
clippy + gauntlet não apanharam (o `planner` saiu limpo):
- **durável, `fsync` do diretório** — o `rename` do `meta.bin` (voto/committed)
  não era tornado durável com um fsync do diretório-pai; um crash podia reverter
  o voto → **split-brain**. Corrigido (`fsync_dir`, best-effort: total no Linux
  de produção, no-op documentado no Windows). Idem no `sm_meta` da máquina.
- **durável, falha alta em meta corrompido** — `load_meta`/`load_sm_meta` repunham
  o voto/`applied` a vazio em silêncio num decode falhado; agora **recusam
  arrancar** (um voto persistido nunca é descartado sem ruído).
- **rede, teto de frame** — `read_frame` alocava até ~4 GiB a partir do
  comprimento vindo do fio (DoS/abort); agora há `MAX_FRAME = 256 MiB`.
- **rede, resiliência do `accept`** — um erro de `accept()` matava o servidor
  para sempre; agora recua e continua.
- **rede, honestidade** — o header afirmava keep-alive que o cliente (liga por
  pedido) não faz; corrigido.

+2 testes de segurança (`corrupt_meta_refuses_to_start`,
`read_frame_rejects_oversized`). 20 testes com a feature, 25× sem flake.

---

## Cobertura da auditoria

| Ficheiro | Extração | Verificação adversarial |
|---|---|---|
| SPEC-INDEX.md | ⚠️ falhou (limite de sessão fable-5) — banner escrito por leitura manual | — |
| SPEC-009-u64.md | ✅ | ⚠️ falhou (limite sessão); extração mantida |
| SPEC-010.md | ✅ | ⚠️ falhou (limite sessão); extração mantida |
| SPEC-011.md | ✅ | ⚠️ falhou (limite sessão); extração mantida |
| SPEC-019-028.md | ✅ | ✅ **refuted_count = 0** (nenhum finding refutado) |
| SPEC-029-035.md | ✅ | ⚠️ falhou (limite sessão); extração mantida |

Legenda de veredicto: **false** = afirma existência/auditoria e o símbolo/ficheiro
não existe ou é outra coisa · **misleading** = parcialmente verdade mas induz em
erro (existe algo relacionado, não o descrito) · afirmações de *design/intenção
futura* não são listadas (são legítimas como RFC).

---

## SPEC-INDEX.md — o "Manifesto" grandioso

Estado: **RFC/brainstorm**, não índice de algo implementado. Declara-se
`CONGELADO / DECLARATIVO E DETERMINÍSTICO` e `CONGELADO E SELADO`, descreve uma
"Data Computation Platform" com dual-compiler, HQL, Arrow Flight, WASM, cost-based
JIT — **nada disto existe no código**. Contradiz a tese fundadora do próprio
projeto (`SPEC.md`): SPEC.md tem como **não-objetivo** "inventar uma linguagem de
consulta nova" e usa **GQL** (`gql.pest`); o manifesto diz "a inteligência vive no
agente, não no banco" e depois enche o banco de compiladores e feedback adaptativo.
*(A extração automática deste ficheiro falhou por limite de sessão; banner escrito
por leitura manual — as contradições acima já tinham sido verificadas na análise
inicial.)*

---

## SPEC-009-u64.md — "CONGELADA / ALINHADA COM O CORE"

Estado real: os **factos numéricos conferem** (EventId é ULID 128-bit;
GraphIndex projeta EventId→u32 denso em ordem de LSN), mas **os dois artefactos
que a spec existe para especificar não existem**.

| Linha | Afirmação | Veredicto | Evidência |
|---|---|---|---|
| 3 | "Status: CONGELADA / ALINHADA COM O CORE" | misleading | `CanonicalKeyCodec` e `DenseEntityMap` = zero ocorrências em `crates/`. "Alinhada com o core" sugere spec verificada contra código. |
| 27 | "A auditoria do código-fonte... revelou..." | misleading | A conclusão (ULID) confere, mas atribui-a a `vm/codec.rs` — que é o codec de frames `VmInstruction` da H-VM — e coloca nesse ficheiro um `CanonicalKeyCodec` inexistente. |
| 50 | `// heraclitus-core/src/vm/codec.rs` `pub struct CanonicalKeyCodec;` | **false** | `vm/codec.rs` existe mas é o codec binário de `VmInstruction` (M20.1). `CanonicalKeyCodec` não existe em ficheiro nenhum. Bloco apresentado como conteúdo real de um ficheiro nunca escrito. |
| 47 | "O método `encode_f64` realiza o colapso canônico de NaN..." | **false** | Não existe `encode_f64`/`encode_i64`/`SIGN_BIT_MASK`. O único encoder f64→u64 real é `f64_ordered` em `heraclitus-index-attr/src/lib.rs:52` — que **não** trata NaN nem -0.0. |
| 123 | `// heraclitus-index-graph/src/dense_map.rs` | **false** | O ficheiro não existe (a pasta tem lib/adaptive/decision/entity/temporal). `DenseEntityMap`/`FrozenDenseEntityMap` = zero hits. Linha 128 declara `EventId = [u8;16]`, contradizendo o real `EventId(pub ulid::Ulid)`. |
| 30 | "GraphIndex projeta... u32 denso em ordem de LSN" | ✅ true | Confere: `index-graph/src/lib.rs:26-28` + `apply()`. |

---

## SPEC-010.md — design puro (sem selos), mas caracteriza mal o código atual

Estado real: **documento de design** (sem claims de auditoria/CONGELADO/notas).
O problema é dizer que o log atual não tem o que **já tem**, e propor como novo o
que já existe sob outro nome.

| Linha | Afirmação | Veredicto | Evidência |
|---|---|---|---|
| 17 | "...`scan_capped`... **sem metadados estruturais**" | misleading | Falso: o log **já** é segmentado em `.hrkl` com `SegmentHeader`+`SegmentFooter` (record_count, min_lsn, max_lsn, raiz Merkle blake3 — `format.rs:95-100`) + `SegmentMeta`/`SegmentIndex`/`LogCatalog` em memória. |
| 39 | "...tabela indexada em memória... (`SegmentCatalog`)" | misleading | Já existe: `LogCatalog {sealed, active}` + `SegmentIndex` (`log/lib.rs:62-76`). Os símbolos `SegmentCatalog`/`SegmentState`/`SegmentMetadata` do spec não existem; o análogo real é `SegmentMeta` (sem timestamps/compression_type). |
| 232 | "raiz Merkle... salva no seu rodapé" | ✅ true | Já implementado: `SegmentFooter.blake3_root` escrito ao selar (`log/lib.rs:1464`). Mas "Fase 3 (Freeze)" não existe como fase nomeada — o análogo é o *sealing*. |
| 233 | "durante reconstrução... recomputa a assinatura... aborta por divergência" | misleading | O replay real (`views/lib.rs:140-190`) **não** recomputa Merkle nem aborta. Há CRC-32 por registo no decode + verificação Merkle só via `verify_segment` (CLI `check`), não durante replay. |
| 245 | "O operador `WHY` deixa de ser... busca bidirecional simplificada" | misleading | `WHY` existe mas é BFS **unidirecional** de ancestrais (`trace_causes`, `backend.rs:1476`), não bidirecional. A "Provenance Engine" de 1ª classe não existe. |
| 212 | "`heraclitus-analytics` intercepta query complexa... quatro componentes" | misleading | `analytics` é um wrapper SQL DataFusion de ~170 linhas sobre a tabela `events`; não intercepta grafo. Statistics/Cardinality/CostModel/PhysicalPlanner/`GraphOperator` = zero hits. |

Genuinamente confere (estado atual bem descrito): materialização Arrow sem poda
(`analytics/lib.rs:65`), replay single-thread (`views/lib.rs:158`), `GraphIndex`
existe.

---

## SPEC-011.md — "Matriz de Maturidade" com cinco notas 10.0 auto-atribuídas

Estado real: **design puro**. Nenhum componente especificado existe; o único nome
coincidente (`StorageEngine`) é uma **variante de erro**, não uma trait.

| Linha | Afirmação | Veredicto | Evidência |
|---|---|---|---|
| 181 | "Abstração de Armazenamento — **10.0** — a trait `StorageEngine`..." | **false** | Não existe trait `StorageEngine`. Só `HeraclitusError::StorageEngine(String)` em `core/src/error.rs:11`. `append_raw`/`fetch_segment`/`write_manifest` + `DatabaseManifest` = zero hits. |
| 182 | "Consistência de Visão — **10.0** — `TransactionSnapshot`..." | misleading | `TransactionSnapshot` não existe. Real: `pub struct Snapshot(Lsn)` (`txn/lib.rs:16`) — newtype de 1 LSN, sem `watermark_lsn`/`visible_segments`. |
| 183 | "Agnosticismo de Artefatos — **10.0** — `DerivedExecutionArtifact`..." | **false** | `DerivedExecutionArtifact`/`ArtifactManager`/`ArtifactType`/`QueryFingerprint` = zero hits. Índices reais não partilham trait de ciclo de vida. |
| 184 | "Proteção de Hardware — **10.0** — `Memory Manager`+`ResourceScheduler`..." | **false** | `MemoryManager`/`ResourceScheduler`/`SystemResources`/`GraphOperator`/zonas Hot-Warm-Cold = zero hits. O único "cold" é `ColdTier` (tiering p/ object storage), não gestão de RAM. |
| 185 | "Determinismo Lógico — **10.0**" | misleading | Nota a uma garantia sem mecanismo: não há PhysicalPlanner/GraphOperator/múltiplas estratégias entre as quais exigir/testar determinismo. |
| 187 | "...atinge maturidade máxima... chancelado e pronto para a codificação" | misleading | "Chancelado" autodeclarado; nada existe em código. Atenuante: "pronto para a codificação" admite que o código não existe. |

---

## SPEC-019-028.md — verificação adversarial completa: **0 refutados**

Design puro com 3 claims concretos de código, **todos confirmados problemáticos**
(o verificador adversarial tentou refutar e não conseguiu).

| Linha | Afirmação | Veredicto | Evidência |
|---|---|---|---|
| 72 | "consenso de replicação... implementado via Raft no crate `heraclitus-raft`" | misleading | `raft/lib.rs` (153 l.) nega no header: "v0 (RFC-003): single-leader log shipping... we do NOT claim automatic failover". Só `Follower::sync_once` + `LogTransport`. `openraft` nem é dependência. |
| 251 | `EventKind { ... SystemMetric }` em `core/src/event.rs` | **false** | Enum real: `{Observation, Action, Message, RetrievalFeedback, FactDerived, DemotionReceipt, Custom}` — sem `SystemMetric`. Zero telemetria endógena. Shape inventado atribuído a ficheiro real. |
| 263 | "...usa `heraclitus-analytics` e a sintaxe SQL/HQL para investigar a si mesmo" | misleading | `analytics` é SQL DataFusion real, mas "HQL" = zero hits (é GQL). A query exemplo (`WHERE kind='SystemMetric'`, colunas `freeze_duration_ms`) nunca devolveria nada — colunas/eventos inexistentes. |
| 350 | "...perfeitamente amarradas e consolidadas. Deixa de ser um desenho teórico" | misleading | Zero hits para todos os componentes das SPEC-019–028 (também sob nomes alternativos). Continua 100% desenho teórico. |

---

## SPEC-029-035.md — output de chat de LLM colado como spec

Estado real: abre com **bajulação ao interlocutor** ("O seu parecer é definitivo..."),
admite ser pré-código (linha 3), e fecha com decreto auto-emitido
**"CONGELADO, CHANCELADO E APROVADO PARA IMPLEMENTAÇÃO IMEDIATA"**. Nenhum
componente nomeado existe.

| Linha | Afirmação | Veredicto | Evidência |
|---|---|---|---|
| 1 | "O seu parecer é definitivo e eleva o projeto ao nível mais alto..." | misleading (bajulação) | Abertura de resposta de LLM; não há "parecer" no repo. |
| 15 | "`DatabaseManifest`... `StorageFormatVersion` (major/minor/feature_flags)" | **false** | Zero hits. Formato real: magic "HRKL" + `format_version: u16` (FORMAT_VERSION=5), sem tripla nem bitmask. |
| 63 | "`ArtifactRegistry` rastreia a árvore de derivação física" | **false** | `ArtifactRegistry`/`ArtifactDependencyNode` = zero hits. Sem DAG de artefactos. |
| 76 | "`MemoryManager` expurga artefato da RAM..." | **false** | `MemoryManager` = zero hits. Sem evicção em cascata. |
| 119 | "`StatisticsCatalog` consome feedbacks... média móvel exponencial" | **false** | `StatisticsCatalog`/`ExecutionFeedback`/`CostModel` = zero hits. Sem malha adaptativa de custo. |
| 133 | "`ResourceScheduler` obriga core pinning das threads do GraphBLAS" | **false** | `ResourceScheduler`/GraphBLAS = zero hits. NUMA só como comentário em `mmap.rs`. Sem core pinning. |
| 179 | "Todos os plugins... executados dentro de um runtime WASM embarcado" | **false** | wasmtime/extism/wasm/`ExtensionCapabilities`/plugin/sandbox = zero hits. Sem sistema de plugins. |
| 204-206 | "Gate 1/2/3... Blindagem de Identidade / EBR / Sandbox WASM" | **false** | `StableId`/EBR/crossbeam-epoch/sandbox WASM = zero hits. "Formalizado" só neste texto. |
| 208 | "CONGELADO, CHANCELADO E APROVADO PARA IMPLEMENTAÇÃO IMEDIATA" | **false** | Decreto auto-emitido; o código real divergiu por completo destas specs. |

---

## Ação recomendada (Fase 0 do PLANO-SPECS.md)

1. **Rebaixar** toda a pasta `SPEC-new/` de "SPEC congelada" para **RFC/proposta**
   (banners aplicados no topo de cada ficheiro em 2026-07-08/09).
2. **Não citar** estes documentos como estado de implementação.
3. **Extrair** as ~5 ideias boas e compatíveis (segment footers com zone maps/bloom,
   delta-of-delta, format versioning completo, EBR, merge determinístico) como RFCs
   pequenos — ver Fases 2–3 do [PLANO-SPECS.md](../PLANO-SPECS.md).
4. **Rejeitar** HQL (SPEC-023): manter GQL, como o código já decidiu.
