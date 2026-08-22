# heraclitus-qualifier

Ferramenta de evidência de desenvolvimento para a SPEC-0049. Ela ainda não é
um certificador de release nem pode marcar uma build como pronta para produção.

O primeiro comando reutiliza o crash-loop real de `heraclitus-log`, captura
stdout/stderr, ambiente, commit, digests e produz `manifest.json` em um
diretório novo. Q1 e Q3–Q6 ficam explicitamente `Inconclusive`; por isso o
resultado global é sempre `UNQUALIFIED`, mesmo quando Q2 passa.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\heraclitus-qualifier\heraclitus-qualifier.ps1 -SelfTest

powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\heraclitus-qualifier\heraclitus-qualifier.ps1 `
  -QualificationCommand q2-crash-loop -Iterations 25 -Out .\qa-evidence\q2-20260821
```

O diretório de saída deve ser novo. A ferramenta usa `--offline`, nunca
sobrescreve evidência existente e grava `manifest.sha256` ao lado do manifesto.
