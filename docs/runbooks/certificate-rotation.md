# Rotação de certificados

TLS e mTLS. Duas situações muito diferentes com a mesma mecânica: **expiração
planeada** e **comprometimento**. A segunda não tem janela de manutenção.

## Onde vivem

```toml
tls_cert_path      = "/etc/heraclitus/tls/server.crt"   # cadeia do servidor
tls_key_path       = "/etc/heraclitus/tls/server.key"   # chave privada
tls_client_ca_path = "/etc/heraclitus/tls/clients-ca.crt"  # CA de clientes (mTLS)
```

Quando `tls_client_ca_path` está definido, o gRPC **exige** certificado de
cliente. É o que separa "o canal está cifrado" de "sei quem está do outro lado".

## Rotação planeada

**1. Avisar antes de expirar, não depois.** Verifique a validade:

```bash
openssl x509 -in /etc/heraclitus/tls/server.crt -noout -enddate
```

Trate < 30 dias como tarefa e < 7 dias como incidente.

**2. Colocar o material novo ao lado do antigo**, com nomes distintos. Não
sobrescreva: se o certificado novo estiver errado, o antigo ainda é a única
coisa que põe o serviço de pé.

**3. Confirmar que a chave corresponde ao certificado** antes de reiniciar
seja o que for:

```bash
openssl x509 -noout -modulus -in server-novo.crt | openssl sha256
openssl rsa  -noout -modulus -in server-novo.key | openssl sha256
```

Os dois digests têm de ser iguais. Este passo custa dez segundos e evita o
arranque falhado mais comum que existe.

**4. Apontar a configuração ao material novo e qualificar:**

```bash
heraclitus-qualifier doctor --config /etc/heraclitus/heraclitus.toml
```

O doctor confirma que os três caminhos existem e que cert e key estão
definidos **em conjunto** — meio par configurado é finding Blocking.

**5. Reiniciar e verificar o handshake de facto:**

```bash
openssl s_client -connect <host>:7474 -servername <host> </dev/null 2>/dev/null | openssl x509 -noout -dates
```

Não confie no `healthz`: ele responde em HTTP no REST de admin e não prova nada
sobre o TLS do gRPC.

**6. Só depois** arquivar o material antigo. Guarde-o até o serviço ter
sobrevivido a um ciclo completo de clientes a ligar-se.

## Rotação da CA de clientes (mTLS)

Trocar a CA invalida **todos** os certificados de cliente de uma vez. Se
trocar a CA e os certificados dos clientes no mesmo instante, corta o acesso a
toda a gente ao mesmo tempo.

A sequência que não corta o serviço:

1. emitir a CA nova;
2. configurar o servidor para aceitar **as duas** CAs (bundle com ambas);
3. re-emitir os certificados de cliente sob a CA nova, cliente a cliente;
4. confirmar que já ninguém apresenta certificado da CA antiga;
5. remover a CA antiga do bundle.

O passo 4 é o que se salta com pressa, e é o que faz um cliente esquecido
descobrir o problema num sábado.

## Comprometimento

Uma chave privada comprometida não tem janela de manutenção.

1. **Emitir material novo imediatamente** e trocar — a indisponibilidade curta
   é preferível a um canal que um terceiro consegue ler.
2. **Revogar o certificado antigo** na CA.
3. Se a chave comprometida era a de uma CA de clientes: **todos** os
   certificados que ela emitiu são suspeitos. Trate como comprometimento
   completo do controlo de acesso e siga
   [incident-response.md](incident-response.md).
4. **Preservar prova** antes de limpar: quem teve acesso, desde quando, e o que
   os registos de auditoria mostram nesse período.
5. Rode também tudo o que a chave protegia e que possa ter passado por esse
   canal — tokens de acesso, credenciais RBAC.

A pergunta que importa e que quase ninguém faz: **o que é que passou por este
canal enquanto a chave esteve comprometida?** Se `audit_queries` estava ligado,
a resposta está no log; se não estava, a resposta é "não sabemos", e isso vai
no relatório do incidente tal e qual.

## O que a rotação não resolve

Rodar certificados não invalida sessões nem tokens já emitidos. Se o problema
era um acesso indevido e não o canal, ver
[incident-response.md](incident-response.md).
