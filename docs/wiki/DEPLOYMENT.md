# Implantação

## Perfis de implantação

O HeraclitusDB deve ser implantado conforme o nível de criticidade do ambiente, não com uma receita única para tudo. Para governo e infraestrutura crítica, a topologia precisa refletir classificação da informação, disponibilidade, conectividade, modelo de ameaça e capacidade operacional da equipe.

## Perfil A — Laboratório

Uso para desenvolvimento, avaliação funcional e provas de conceito sem dados sensíveis.

```text
1 host
├─ heraclitus-server
├─ CLI / SDK
└─ armazenamento local
```

Requisitos mínimos: build reproduzível, dataset de teste, logs ativados e procedimento de reset.

## Perfil B — On-premises institucional

Uso em datacenter ou nuvem privada do órgão.

```text
Clientes internos
      │
      ▼
Reverse proxy / controle de acesso
      │
      ▼
HeraclitusDB nodes
      │
 ┌────┴─────┐
 ▼          ▼
Storage   Backup
```

Recomendações:

- segmentar plano de dados, plano de administração e observabilidade;
- restringir portas administrativas;
- usar identidade institucional e segregação de funções;
- externalizar backup para domínio de falha diferente;
- manter artefatos e configuração sob controle de versão;
- registrar hash, versão e commit do binário em produção.

## Perfil C — Alta disponibilidade

Quando a indisponibilidade tem impacto institucional, utilizar a camada de replicação adequada e testar falha real de nó, rede, storage e processo.

O simples fato de existirem múltiplos nós não cria alta disponibilidade. É necessário validar eleição, quorum, RPO, RTO, recuperação e comportamento sob partição.

## Perfil D — Rede restrita / air-gapped

Ambientes desconectados exigem disciplina adicional:

- mirror ou vendor de dependências;
- repositório interno de artefatos;
- SBOM e assinaturas transportadas junto do release;
- relógio confiável e política de sincronização;
- processo formal de importação/exportação;
- atualização offline de indicadores e listas de revogação quando aplicável;
- kit de rollback local;
- documentação disponível sem depender da Internet.

## Build

Build básico:

```bash
git clone https://github.com/JoseRFJuniorLLMs/HeraclitusDB.git
cd HeraclitusDB
cargo build --release
```

O workspace também possui perfil `native`, voltado a builds locais otimizados para a CPU da máquina. Binários compilados com instruções específicas não devem ser distribuídos como universais.

## Checklist antes de subir um ambiente

- [ ] versão e commit aprovados;
- [ ] build e dependências identificados;
- [ ] configuração revisada por pares;
- [ ] diretórios de dados e permissões validados;
- [ ] portas e ACLs documentadas;
- [ ] autenticação/autorização configuradas conforme a superfície usada;
- [ ] backup e restauração testados;
- [ ] logs e métricas chegando ao destino institucional;
- [ ] limites de recursos definidos;
- [ ] política de chaves e segredos aplicada;
- [ ] plano de rollback ensaiado;
- [ ] procedimento de incidente conhecido pela equipe.

## Dados de produção

Nunca use a primeira prova de conceito como produção por inércia. Separe ambientes, identidades, chaves, dados e artefatos. Bancos acabam virando infraestrutura crítica exatamente quando alguém percebe tarde demais que o “teste temporário” está sustentando um processo essencial há oito meses.

## Leitura complementar

- [`../getting-started/quickstart.md`](../getting-started/quickstart.md)
- [`../runbooks/`](../runbooks/)
- [`../qualification/`](../qualification/)
- [`../BLOQUEIOS-PRODUCAO.md`](../BLOQUEIOS-PRODUCAO.md)
