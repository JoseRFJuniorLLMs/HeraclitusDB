# Pacotes Linux

As releases a partir de 3.0.4 distribuem o tarball e pacotes nativos x86_64
`.deb` e `.rpm`, com checksums e atestação do CI. As dependências são derivadas
dos binários efetivamente empacotados; confira a versão de glibc exigida pelo
pacote antes de instalar em uma distribuição mais antiga que o runner de build.

Os pacotes não iniciam nem habilitam o serviço automaticamente. A configuração
de referência usa loopback. Configure credenciais e a exposição de rede antes
de habilitar a unidade `heraclitusdb.service`. Os diretórios de dados são
gerenciados pelo systemd e não são removidos na desinstalação.

O `.deb` pode ser instalado com `sudo apt install ./heraclitusdb_*_amd64.deb`.
O `.rpm` pode ser instalado com `sudo dnf install ./heraclitusdb-*.x86_64.rpm`.
Uma atualização preserva alterações em `/etc/heraclitusdb/heraclitus.toml`.
Para usar o TOML, acrescente o caminho à linha `ExecStart` por um override da
unidade, conforme os comentários da configuração distribuída.

O empacotador recebe uma pasta de release já qualificada, a versão e a pasta
de saída: `bash packaging/build-linux-packages.sh DIST VERSION OUT`. Ele requer
`dpkg-dev`, `rpm` e ferramentas padrão GNU. Nenhum binário é recompilado ou
alterado durante o empacotamento.
