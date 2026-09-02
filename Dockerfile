# HeraclitusDB — imagem de servidor.
#
# ESTADO: escrito a 2026-09-02 e NUNCA CONSTRUÍDO — a máquina onde nasceu não
# tinha Docker. Trate a primeira construção como parte da revisão, não como uma
# formalidade. O modo de falha é ruidoso (a build pára), não silencioso.
#
#   docker build -t heraclitus:1.0.5 .
#   docker run --rm -p 7474:7474 -p 7475:7475 -v heraclitus-data:/var/lib/heraclitus heraclitus:1.0.5
#
# Features: a imagem constrói o conjunto POR OMISSÃO de propósito. `analytics`,
# `tier*` e `gpu` puxam dependências pesadas (DataFusion, arrow/parquet, wgpu) e
# mudam o binário que se qualifica — uma imagem "com tudo" seria um artefacto
# diferente do que a suíte de qualificação assina. Para as ligar, passe
#   --build-arg CARGO_FEATURES="analytics,tier"
# e qualifique essa imagem separadamente.

ARG RUST_VERSION=1.96.0

# ── build ────────────────────────────────────────────────────────────────────
FROM rust:${RUST_VERSION}-bookworm AS build

# `protobuf-compiler` está aqui como rede de segurança: o `heraclitus-proto`
# compila os .proto com `protox` (puro Rust) e não deveria precisar de `protoc`,
# mas uma mudança de build-dependency que volte a exigi-lo falharia aqui de
# forma obscura. O custo é uns megabytes numa etapa que não vai para a imagem
# final.
RUN apt-get update \
 && apt-get install -y --no-install-recommends protobuf-compiler \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# O workspace inteiro. Não se faz o truque de copiar só os manifestos para
# cachear dependências: com ~30 crates locais e caminhos relativos entre eles,
# essa optimização exige manter uma lista de COPY sincronizada à mão, e uma
# lista dessas envelhece em silêncio — apanha-se com um build partido meses
# depois. Prefere-se uma build mais lenta a uma cache que mente.
COPY . .

ARG CARGO_FEATURES=""
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    set -eux; \
    if [ -n "$CARGO_FEATURES" ]; then \
      cargo build --release --locked -p heraclitus-server --bin heraclitus-server --features "$CARGO_FEATURES"; \
    else \
      cargo build --release --locked -p heraclitus-server --bin heraclitus-server; \
    fi; \
    # A cache de `target` é um mount: o binário TEM de sair de lá antes de a
    # etapa acabar, senão desaparece com o mount e o COPY seguinte não o encontra.
    cp target/release/heraclitus-server /usr/local/bin/heraclitus-server

# ── runtime ──────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# `ca-certificates` para o tier na nuvem e para o carimbo RFC3161 falarem TLS;
# `curl` só para o HEALTHCHECK abaixo.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 heraclitus \
 && useradd --system --uid 10001 --gid heraclitus --home /var/lib/heraclitus heraclitus \
 && mkdir -p /var/lib/heraclitus /var/log/heraclitus \
 && chown -R heraclitus:heraclitus /var/lib/heraclitus /var/log/heraclitus

COPY --from=build /usr/local/bin/heraclitus-server /usr/local/bin/heraclitus-server

USER heraclitus:heraclitus
WORKDIR /var/lib/heraclitus

# O log é a verdade e vive aqui. Sem um volume montado neste caminho, o banco
# morre com o contentor.
VOLUME ["/var/lib/heraclitus"]

ENV HERACLITUS_DATA_DIR=/var/lib/heraclitus \
    HERACLITUS_LOG_DIR=/var/log/heraclitus \
    HERACLITUS_GRPC_ADDR=0.0.0.0:7474 \
    HERACLITUS_REST_ADDR=0.0.0.0:7475

EXPOSE 7474 7475

# `/healthz` e não `/stats`: o `/stats` percorre o manifesto e toma os locks dos
# índices, e uma sonda de saúde nunca deve depender de trabalho pesado. (Ver o
# comentário do `Shared` em crates/heraclitus-server/src/engine.rs sobre o
# checkpoint.) `start-period` generoso porque um arranque a frio replaya a cauda
# do log — com milhões de eventos isso não é instantâneo.
HEALTHCHECK --interval=15s --timeout=5s --start-period=300s --retries=5 \
  CMD curl -fsS http://127.0.0.1:7475/healthz || exit 1

# Sem argumento, o servidor lê a configuração das variáveis HERACLITUS_*.
# Para um TOML, monte-o e passe o caminho: CMD ["/etc/heraclitus/config.toml"].
ENTRYPOINT ["/usr/local/bin/heraclitus-server"]
