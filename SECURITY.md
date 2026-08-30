# Política de segurança

Relate vulnerabilidades de forma privada pelo recurso **Security Advisories** do
repositório. Não publique dados pessoais, credenciais, amostras de logs de
clientes ou detalhes exploráveis em issues públicas.

O fluxo completo de triagem, severidade, SLA, release emergencial,
divulgação coordenada e regressão está em
[`docs/security/vulnerability-response.md`](docs/security/vulnerability-response.md).

## Gate de dependências

O CI executa `cargo audit --deny warnings` e falha para qualquer achado que não
esteja explicitamente listado abaixo. Uma exceção não significa que o advisory
foi resolvido; significa que o risco foi analisado, limitado e tem condição de
revogação verificável.

| Advisory | Situação em 2026-08-14 | Contenção e condição de revogação |
|---|---|---|
| `RUSTSEC-2026-0235` (`rkyv 0.7.46`) | Presente somente no `Cargo.lock` como feature opcional de `rust_decimal`; não aparece no grafo resolvido nem com `--all-features`. | O CI prova que `cargo tree --workspace --all-features -i rkyv` está vazio. Se entrar no grafo compilado, o build falha e a exceção deixa de ser válida. |
| `RUSTSEC-2025-0141` (`bincode 2.0.1`, não mantido) | Sem vulnerabilidade conhecida, mas é formato legado de segmentos, checkpoints e mensagens internas. | Todos os comprimentos externos são limitados e os registros têm verificação de integridade. A remoção exige uma nova versão de formato com leitura retrocompatível; nenhuma entrada nova de rede deve adotar bincode. |
| `RUSTSEC-2024-0436` (`paste 1.0.15`, não mantido) | Macro transitiva de Arrow/Parquet, usada em compilação. | Acompanhar a remoção pelo upstream. Se surgir vulnerabilidade executável ou alternativa compatível, atualizar imediatamente. |

O SDK Python é auditado separadamente com `pip-audit --strict`. A revisão destas
aceitações é obrigatória antes de cada release e, no máximo, a cada 30 dias.
