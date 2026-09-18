# Deep-RedTeam-Heraclitus

Laboratório adversarial **autorizado, loopback-only e orientado a invariantes** para superfícies profundas do HeraclitusDB que não são bem cobertas apenas por fuzzing de parser ou pelo Agent-Atack-Heraclitus.

O laboratório antigo continua sendo a referência para MCP, Agent Gateway, approvals, replay, prompt-injected agents e evidência de chamadas. Este laboratório complementa aquela cobertura com cinco campanhas:

1. **Cross-Tenant Attack Campaign**
2. **Privileged Admin Crash/Fault Campaign**
3. **Expensive Query / Resource Isolation Campaign**
4. **HRKL Rollback & Evidence Substitution Campaign**
5. **Raft Hostile Peer / Snapshot Boundary Campaign**

## Regra de segurança

O runner recusa qualquer URL ou host de rede que não seja localhost, 127.0.0.1 ou ::1. Não existe opção para remover essa trava.

Mutações de HRKL acontecem somente em cópias dentro de diretórios temporários. O fault injector só mata processos-filho que o próprio runner iniciou.

Isso torna a suíte adequada para desenvolvimento e qualificação controlada sem transformar um teste de invasão numa excursão acidental pela infraestrutura alheia, um hobby que costuma terminar em reuniões.

## Uso rápido

Validar o próprio harness:

~~~bash
python3 labs/Deep-RedTeam-Heraclitus/runner.py --self-test
~~~

Executar com a configuração de laboratório:

~~~bash
cd labs/Deep-RedTeam-Heraclitus
python3 runner.py --config config.example.json
~~~

O relatório JSON é gravado em:

~~~text
reports/<campaign>.json
~~~

## 1. Cross-Tenant Attack Campaign

A campanha usa duas identidades sintéticas e tenta acessar recursos do tenant A usando a credencial do tenant B.

Ela é deliberadamente configurável porque o HeraclitusDB possui superfícies em estágios diferentes de maturidade multi-tenant. O teste não deve inventar isolamento que o deployment não afirma possuir.

~~~text
credential A -> tenant A -> ALLOW
credential B -> tenant A -> DENY
~~~

Cobertura esperada na qualificação completa:

- telemetry health;
- security events;
- Agent Evidence;
- bundles/export;
- graph;
- text;
- vector;
- analytics;
- cold recall;
- AS OF;
- backup/export.

A identidade autenticada deve dominar qualquer tenant informado por query string, body ou header.

## 2. Privileged Admin Crash/Fault Campaign

O modo admin_fault inicia uma instância de laboratório usando uma cópia do seed data, dispara uma operação administrativa e mata **somente aquele processo-filho** em vários instantes.

Cut points iniciais:

~~~text
0 ms
10 ms
50 ms
200 ms
~~~

A configuração aceita o placeholder {data_dir} em server_argv, operation_argv e verify_argv.

Use o driver para operações como crypto-shred, Legal Hold, remoção de Legal Hold, rotação/destruição de chave, mudança de política, GC administrativo e aprovação humana irreversível.

Invariante:

~~~text
NO DURABLE INTENT
    =>
NO IRREVERSIBLE SIDE EFFECT
~~~

Após crash, o estado deve ser verificável como SUCCEEDED, FAILED ou UNKNOWN/RECONCILE. Nunca como sucesso presumido.

## 3. Expensive Query / Resource Isolation Campaign

A campanha sempre executa duas regressões de segurança de baixo custo quando query.enabled=true:

- tentativa de CREATE EXTERNAL TABLE apontando apenas para um arquivo temporário criado pelo próprio runner;
- tentativa de DML por POST /sql.

Ambas devem ser recusadas.

O stress válido fica **desligado por padrão**. Quando explicitamente ativado em laboratório, executa consultas SQL válidas e concorrentes com limites internos do runner:

- máximo 32 workers;
- máximo 128 requests por campanha;
- timeout máximo de 30 s por request.

A campanha mede sobrevivência do serviço e p95 do lote. Ela não substitui o benchmark Q1.

A qualificação completa deve testar também isolamento de recursos:

~~~text
tenant A gera pressão
tenant B mantém SLO mínimo
~~~

## 4. HRKL Rollback & Evidence Substitution Campaign

Com hrkl.enabled=true, o runner:

1. copia o fixture para diretório temporário;
2. verifica um segmento intacto;
3. altera um único bit na cópia;
4. exige que heraclitus verify --logical rejeite a mutação;
5. executa um rollback de HRKM removendo a geração mais nova em outra cópia;
6. compara o estado com um digest externo do fixture original.

O teste registra explicitamente a diferença entre INTEGRITY e FRESHNESS/ANTI-ROLLBACK.

Um manifesto antigo pode ser internamente válido. Por isso uma linha GOV deve manter um head/root monotônico fora do domínio mutável do host quando quiser provar ausência de rollback.

## 5. Raft Hostile Peer Campaign

Com um cluster de laboratório em loopback, a campanha atual testa:

- frame TCP com comprimento 0xFFFFFFFF;
- payload bincode malformado;
- sobrevivência do listener após os dois ataques;
- visibilidade explícita da atual fronteira de confiança do transporte.

O transporte TCP atual aceita conexão antes de qualquer identidade de peer. Quando require_authenticated_transport=false, isso gera FINDING, não PASS silencioso.

Quando um deployment futuro exigir peer authentication/mTLS, defina require_authenticated_transport=true e a ausência dessa barreira passa a ser FAIL crítico.

A campanha externa Q5 deve complementar isso com rogue node, snapshot antigo, snapshot adulterado, AppendEntries replay, leader antigo retornando após partition, membership race, follower restaurado de backup antigo e quorum loss/heal.

## Resultados

Cada resultado contém attack_id, campaign, target, expected, observed, outcome, severity_if_failed, duration_ms e detail.

Outcomes:

- PASS — invariante satisfeita;
- FAIL — gate violado;
- FINDING — risco/trust boundary observado e que precisa disposição formal;
- SKIP — superfície não configurada para aquela execução.

SKIP não equivale a qualificação.

## Relação com Q3

A matriz canônica continua em:

~~~text
qa/qualification/matrices/attack-matrix.json
~~~

Uma execução GovernmentProduction deve anexar o relatório deste laboratório à atestação Q3 quando as superfícies correspondentes fizerem parte do deployment avaliado.

Fuzzing continua necessário. Só não deve ser confundido com red team, da mesma forma que um detector de fumaça não é um corpo de bombeiros.
