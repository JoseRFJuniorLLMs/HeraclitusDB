# HeraclitusDB v3.0.4 — Correções das auditorias e pacotes Linux

Data: 2026-10-20. Binários e pacotes são compilados no GitHub Actions. O workflow
de publicação exige dois builds reprodutíveis e qualifica o pacote extraído
com 40 ciclos de crash/restart antes de tornar a release pública.

## Correções

- REST exige autenticação também quando configurado apenas `auth_token`.
  O Basic legado correspondente usa `legacy-admin:<token>`.
- WAL Raft v2 protege cabeçalhos e payloads por checksum, migra atomicamente o
  WAL anterior e propaga falhas de fsync de diretório no Linux.
- Chaves e marcas de shred de identificadores longos usam nomes limitados por
  hash, preservando nomes antigos que cabem no sistema de arquivos.
- Recall frio v1/v6 decifra conteúdo, atributos e embeddings com o keystore do
  banco. O recall v6 usado pelo Engine valida o recibo completo e devolve dados
  da mesma imagem verificada; não confia em um segundo GET nem em ETag.
- Compatibilidade de cifra v1 exige inventário persistido de blobs vinculados
  ao evento e à finalidade originais. Uma substituição v1→evento v2 é recusada.
- Fila Parquet processa os segmentos seguintes após uma falha individual e
  mantém visível o erro agregado, sem avançar o watermark sobre lacunas.
- Retry de append replicado confere todo o episódio, além de seu EventId.
- Limpeza da memtable trata publicação fora de ordem e libera a adjacência.
- Leituras pontuais e varreduras pinam gerações selecionadas contra o GC.

## Otimizações e distribuição

- Scan builtin da cauda sai do mutex do writer e respeita o teto confirmado.
- Cache limitado a 32 leitores PACKED; cursor de arquivo protegido contra
  interleaving de leituras concorrentes.
- Hash idempotente mantém os mesmos bytes canônicos, serializando diretamente
  no hasher, sem alocar o JSON inteiro.
- Publicação v6 elimina a cópia integral extra do segmento.
- Leitores REST do estado H-VM compartilham snapshots por Arc.
- `heraclitus-server --version` inclui SHA, estado clean/dirty e época da fonte.
- CI compila os binários e gera `.deb` e `.rpm` x86_64, além do tarball.
  Instalação dos pacotes mantém o serviço parado para configuração prévia.

## Provas e limites

Sete modelos Lean compilam sem `sorry` nem axiomas específicos do projeto.
O modelo Merkle deixa de assumir a falsa injetividade da soma. O CI verifica
os modelos e gera relatório com commit e escopo. Isso não é uma prova de
refinamento do código Rust: esse estado continua `NOT_VERIFIED`.

O soak reprovado de 20/10 ainda precisa de nova execução e diagnóstico causal.
Esta versão não declara encerradas as otimizações arquiteturais O1/O2/O6/O7/O8,
o teto global dos índices, snapshots Raft em streaming, nem a qualificação
externa HSM/ACT/WORM e institucional. A política conservadora do footer B5 é
mantida para evitar truncar dados possivelmente confirmados.

## Atualização

Faça backup consistente antes da atualização. O WAL novo fica em
`entries.v2.wal`; `entries.wal` é preservado como origem da migração, mas deixa
de ser a autoridade. Não faça downgrade em cima do diretório já atualizado.

Na primeira abertura cifrada sem política de compatibilidade, o log é varrido
em lotes de 1024 registros para registrar os envelopes v1 preexistentes.
Preserve `legacy-bindings.v1` junto ao keystore nos backups e restauros. O
inventário inicial pressupõe dados anteriores confiáveis; alterações ocorridas
antes da criação dessa política exigem verificação/restauro independente.
