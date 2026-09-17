# FAQ

## O HeraclitusDB é um banco de dados?

Sim, mas o projeto vai além do armazenamento convencional. Ele combina log temporal append-only, materialização de estado, índices especializados, query, analytics, agentes e segurança. A identidade central é a preservação verificável da história.

## O projeto é oficial do Governo Federal?

Não. O HeraclitusDB é um projeto independente orientado a requisitos encontrados no setor público e em ambientes regulados. A documentação usa linguagem institucional, mas não implica homologação, adoção ou endosso por órgão público.

## O sistema exige nuvem pública?

Não como premissa arquitetural. O desenho prioriza execução local/on-premises e pode ser preparado para redes restritas. Alguns componentes opcionais podem ter integrações externas conforme configuração.

## Funciona sem LLM?

Sim. O núcleo de persistência, temporalidade, índices e consulta não depende de LLM. Capacidades de agentes e investigação assistida são camadas adicionais.

## O histórico pode ser alterado?

O modelo primário é append-only: mudanças são registradas como novos eventos. A integridade física e lógica precisa ser protegida também por controles de infraestrutura, chaves, permissões e verificação criptográfica.

## Qual a diferença entre backup e replay?

Backup preserva artefatos necessários para recuperação. Replay reconstrói estado derivado a partir do histórico canônico. Eles se complementam e não devem ser tratados como a mesma coisa.

## Índices são a fonte da verdade?

Não. A arquitetura considera índices e views estruturas derivadas. A fonte canônica é o histórico persistido no log.

## Há suporte a grafo, texto e vetor?

O workspace possui crates dedicados a índices de grafo, texto, vetores e atributos, além de uma camada de retrieval para combinar resultados.

## Há replicação?

O workspace possui `heraclitus-raft`. A presença da implementação não elimina a necessidade de qualificar quorum, partições de rede, failover, RPO e RTO na topologia real.

## Há aceleração por GPU?

Existe `heraclitus-gpu` e infraestrutura HUME. A utilização depende de build, hardware, feature set e workload. Deve existir fallback e benchmark reprodutível para qualquer dependência operacional de aceleração.

## O HeraclitusDB é compatível com LGPD?

Nenhum banco é “LGPD-compliant” por simples instalação. O HeraclitusDB pode apoiar controles como rastreabilidade, retenção, auditoria e proveniência, mas conformidade depende do tratamento, finalidade, base legal, governança, controles e processos do controlador/operador.

## O projeto possui ICP-Brasil?

Há uma camada de compliance com mecanismos relacionados a evidência temporal e infraestrutura de certificados conforme configuração do projeto. Uso institucional deve validar cadeia, políticas, fontes de tempo, revogação e requisitos jurídicos aplicáveis ao caso.

## Posso usar em produção hoje?

Avalie os documentos de qualificação e os bloqueios de produção antes de qualquer decisão. O projeto está em evolução ativa e nem todo componente tem o mesmo nível de maturidade.

## Como avaliar o projeto seriamente?

Use uma sequência objetiva: build → testes → dataset representativo → benchmark → crash/recovery → corrupção → backup/restore → upgrade/rollback → segurança → observabilidade → piloto controlado.

## Por que Rust?

Rust oferece controle de memória e desempenho de baixo nível com fortes garantias de segurança de memória no código seguro, o que é útil para infraestrutura de dados. Isso não torna o software automaticamente seguro; apenas remove uma categoria importante de falhas quando o código respeita os limites da linguagem.

## O que significa “soberano” aqui?

Significa priorizar controle local sobre execução, dados, artefatos, dependências e modelos, reduzindo dependências externas obrigatórias. Não é uma alegação política ou certificação formal.
