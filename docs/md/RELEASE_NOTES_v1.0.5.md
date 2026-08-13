# HeraclitusDB v1.0.5 — "fable-5"

**Data:** 2026-08-06

Patch **CRÍTICO** sobre a [v1.0.4](RELEASE_NOTES_v1.0.4.md). Fecha seis defeitos
encontrados numa auditoria recursiva adversarial de todo o código (128 ficheiros,
40k LOC) — incluindo um em que **bit rot num segmento selado apagava o histórico
e reescrevia a raiz Merkle por cima**, transformando a camada de evidência num
carimbo de aprovação para os dados truncados.

> ### ⚠️ Atualização recomendada a todos
> Cinco dos seis são **silenciosos**: sem panic, sem erro no log, sem métrica.
> Um deles é um **DoS remoto** disparado por uma query de sintaxe válida.

**Sem mudanças de API nem de formato em disco.** Verificado verde (msvc): suite
completa **419 passed, 0 failed, 0 ignored** com
`replication`+`analytics`+`tier`+`distill`.

---

## Correções

### Log — bit rot num segmento selado apagava o histórico *(CRÍTICO)*

`Log::open` corria `execute_physical_repair` em **todos** os segmentos, sem
guarda de `is_last` nem de `sealed`. Um único bit invertido a meio de um
segmento já selado provocava, em cadeia:

1. `set_len(valid_len)` — todos os registos a seguir ao ponto corrompido
   **apagados irreversivelmente**, num log que é a "fonte única de verdade";
2. como o footer nunca é alcançado, o ramo de re-selagem escrevia um footer
   **novo** com a raiz Merkle recalculada só sobre os sobreviventes —
   `verify_segment` passava a responder `valid: true`. **A prova blake3 de
   adulteração era destruída, não reportada**;
3. o segmento seguinte mantém o seu `base_lsn`, deixando uma **lacuna de LSN**:
   views reconstruídas do LSN 0 e leituras AS OF viam um histórico com buraco;
4. `Log::open` devolvia `Ok(())` — contra o contrato explícito de
   `heraclitus-core/src/error.rs` (*"`Corruption` is never silently swallowed"*).

Reproduzido: 120 episódios, 1 bit invertido no segmento 2 → 20 registos
perdidos, ficheiro 4060 B → 2020 B, raiz `9a135a5b…` → `286237e9…`,
`verify_segment` **`valid: true`**, lacuna de LSN 97..116.

Uma cauda torn só é legítima no segmento **ativo** (crash a meio de uma
escrita). Num segmento anterior passa a recusar abrir, preservando o ficheiro
para perícia/restauro — a **mesma política que a v1.0.2 já aplicou ao WAL do
raft**; o log de segmentos nunca tinha recebido a guarda equivalente, e é ele a
fonte da verdade. *(commit `25702e3`)*

### Log — `ts` não-monotónico invalidava o `AS OF TIMESTAMP` *(ALTO)*

`Engine::lsn_for_timestamp` faz **busca binária** assumindo `ts` monotónico por
LSN. Mas o carimbo era feito no chamador e só **depois** a mensagem entrava no
canal do worker, que é quem atribui o LSN: dois appends concorrentes
invertiam-se. **Medido: 69 inversões em 1200 registos (5,75%)** — não é uma
corrida rara. A busca binária operava sobre dados desordenados e devolvia
snapshots errados, em silêncio.

O carimbo passa para dentro da secção crítica que enfileira o comando (o worker
consome FIFO ⇒ a ordem dos `ts` é a dos LSNs). A secção é minúscula (um tick do
HLC + um `send`) e a espera pela resposta fica **de fora**, para não serializar
as escritas. Medido depois: **0 inversões em 5 corridas**. *(commit `06010d7`)*

### Log — `scan` engolia registos com CRC violado *(MÉDIO)*

`scan_capped` saltava um registo com CRC-32C violado, avançava o cursor e
devolvia `Ok` com o LSN em falta — enquanto `Log::read` do **mesmo** LSN
devolvia `Corruption`. Os dois caminhos de leitura discordavam.

A consequência mais grave: `ViewRegistry::rebuild` — o caminho oficial
"reconstrói sempre a partir do LSN 0", de que o **invariante I6** depende —
terminava `Ok` com o episódio ausente de todas as views, **e o watermark
persistido avançava para além do buraco**, garantindo que aquele LSN nunca mais
seria reaplicado. Dentro do intervalo comprometido não existe cauda torn, logo
um registo ilegível é corrupção: passa a falhar alto. *(commits `06010d7`,
`b4a569b`)*

### Engine — views indexavam `ts_hlc = 0` *(ALTO — quebra do I6)*

`Engine::append` fazia `log.append(episode.clone())` e depois
`index_applied(lsn, &episode)`: o log carimba o `ts_hlc` na **sua** cópia, logo
as views eram alimentadas com o original, ainda a zero. Ao vivo viam `0`;
reconstruídas do LSN 0 viam o valor real — dois estados diferentes para o mesmo
log. A `activation` é a mais afetada: usa `ts_hlc >> 16` como instante de
acesso, portanto ao vivo registava tudo no instante 0 (recência toda errada).
Novo `Log::append_stamped`. *(commit `0f5f2c9`)*

### Índice de atributos — query válida derrubava as escritas *(ALTO — DoS remoto)*

`lookup_range` passava bounds não validados a `BTreeMap::range`, que **panica**
quando o início é maior que o fim. Uma query GQL de sintaxe **válida** lá chega:
`WHERE n.valor > 100 AND n.valor < 10`. Pior: corre com o Mutex do índice
**bloqueado**, por isso o panic **envenenava-o** — a partir daí todo
`index_applied` falhava e o nó **deixava de aceitar escritas até reiniciar**. Um
único pedido derrubava as escritas do processo. *(commit `0f5f2c9`)*

### H-VM — cliente podia envenenar o ledger soberano *(ALTO)*

`is_hvm` identifica um frame do ledger apenas pela string do kind,
`EventKind::Custom("hvm_isa")` — que qualquer cliente pode escolher num Append
normal. Efeito duplo e **irreversível** (o log é imutável): o episódio passava a
ser saltado por views/attr/memtable, ficando **invisível a todas as queries**; e
o frame entrava no replay do H-VM, onde bytes arbitrários não decodificam como
instrução ISA, **envenenando permanentemente** o ledger. O kind passa a ser
reservado. *(commit `e72c8c0`)*

### Compliance — recibos legítimos eram reportados como fraude *(ALTO)*

`verify_receipt` chamava sempre `verify_dev_token`. Um `.tst` RFC 3161 **real**
(modo `HttpTsa`, produção) nunca descodifica nesse formato, por isso devolvia
exatamente o mesmo erro de uma assinatura adulterada: **todos** os recibos
legítimos de produção apareciam como fraude. Agora distingue-se "não consigo
validar este formato" de "a assinatura não confere". *(commit `8709fdf`)*

### Outras

- **`/hvm/checkpoint` ressuscitava registos apagados** — `from_map` abria a
  árvore existente e só fazia upsert; é um snapshot de estado, não um delta.
- **Bytes binários corrompidos** por `from_utf8_lossy` em três superfícies de
  leitura (o cold tier é o único caminho de leitura dos dados demovidos e
  devolvia-os corrompidos com `200 OK`). *(commit `fcf9b7a`)*

---

## Limitação conhecida (documentada, não corrigida)

**Os recibos forenses são forjáveis.** `verify_dev_token` valida a assinatura
com a chave pública transportada **dentro do próprio token**, sem âncora de
confiança — quem forjar um par de chaves produz um recibo que passa. O
`LocalTsa` gera chave nova a cada arranque, portanto não existe sequer âncora
estável para fixar: é uma autoridade de **desenvolvimento**. Deteta corrupção
acidental, **não** um adversário. Prova forense a sério exige encadear o
certificado do signatário às raízes ICP-Brasil — milestone por fazer, agora
explícito no código em vez de implícito.

---

**Instalação/upgrade:** substituir o binário. Formatos de log, checkpoint e WAL
**inalterados** — rolling upgrade seguro, sem migração.

> **Nota operacional:** esta versão passa a **recusar arrancar** quando encontra
> corrupção a meio de um segmento não-ativo, em vez de truncar em silêncio. Se
> um nó não arrancar depois do upgrade, isso é a deteção a funcionar: o segmento
> indicado tem bit rot e deve ser restaurado de backup ou de uma réplica — os
> dados que antes desapareciam sem aviso continuam lá, no ficheiro preservado.
