# Desenvolvedor: Jose R F Junior
# web2ajax@gmail.com
# joseribamar.junior@inss.gov.br

"""Cliente Python amigável para o HeraclitusDB (gRPC).

Exemplo:

    import heraclitusdb
    db = heraclitusdb.connect("127.0.0.1:7474")

    db.append("Observation", "empresa X trocou de sócio", attrs={"caso": "1"})
    rows = db.query('MATCH (n) RETURN n LIMIT 10')
    df   = db.query_df('MATCH (n) RETURN n LIMIT 100')      # -> pandas.DataFrame
    past = db.query('MATCH (n) RETURN n', as_of=1000)        # viagem no tempo
    print(db.verify())                                       # escudo Merkle
"""

import json
import os

import grpc

from . import heraclitus_pb2 as pb
from . import heraclitus_pb2_grpc as rpc


class HeraclitusError(RuntimeError):
    """Erro de comunicação/execução com o HeraclitusDB."""


def _loads(text):
    """JSON → objeto; se não for JSON (ex.: plano do EXPLAIN), devolve o texto."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return text


class Client:
    """Conexão a um servidor HeraclitusDB."""

    def __init__(
        self,
        addr="127.0.0.1:7474",
        *,
        tls=False,
        root_certificates=None,
        private_key=None,
        certificate_chain=None,
        server_name=None,
        max_message_mb=256,
        token=None,
        timeout=30.0,
    ):
        self.addr = addr
        self.timeout = float(timeout) if timeout is not None else None
        # Quando o servidor exige autenticação (config.auth_token), enviamos
        # `authorization: Bearer <token>` em cada chamada. O token pode vir do
        # argumento ou, por omissão, da env HERACLITUS_TOKEN — assim todos os
        # clientes (memória, console, MCP, ETLs) ficam autenticados de uma vez.
        # Sem token -> lista vazia (sem auth, compatível com servidor aberto).
        if token is None:
            token = os.environ.get("HERACLITUS_TOKEN")
        if token is None:
            token_file = os.environ.get("HERACLITUS_TOKEN_FILE")
            if token_file:
                try:
                    with open(token_file, encoding="ascii") as handle:
                        token = handle.read().strip()
                except OSError as exc:
                    raise ValueError(f"não foi possível ler HERACLITUS_TOKEN_FILE: {exc}") from exc
                if not token:
                    raise ValueError("HERACLITUS_TOKEN_FILE está vazio")
        self._md = [("authorization", f"Bearer {token}")] if token else []
        # Queries amplas (ex.: MATCH (n) RETURN n) podem devolver dezenas de MB;
        # o default gRPC (4 MB) estoura. Subimos o limite de envio/receção.
        options = [
            ("grpc.max_receive_message_length", int(max_message_mb) * 1024 * 1024),
            ("grpc.max_send_message_length", int(max_message_mb) * 1024 * 1024),
        ]
        if server_name:
            options.append(("grpc.ssl_target_name_override", str(server_name)))
        if tls:
            if (private_key is None) != (certificate_chain is None):
                raise ValueError(
                    "private_key e certificate_chain devem ser fornecidos juntos para mTLS"
                )
            creds = grpc.ssl_channel_credentials(
                root_certificates=root_certificates,
                private_key=private_key,
                certificate_chain=certificate_chain,
            )
            self._channel = grpc.secure_channel(addr, creds, options=options)
        else:
            self._channel = grpc.insecure_channel(addr, options=options)
        self._stub = rpc.HeraclitusStub(self._channel)

    # ── escrita ──────────────────────────────────────────────────────────
    def append(
        self,
        kind,
        content,
        *,
        agent_id="",
        session_id="",
        attrs=None,
        parents=None,
        hyp=None,
        sph=None,
        euc=None,
        idempotency_key="",
        timeout=None,
        return_metadata=False,
    ):
        """Acrescenta um episódio ao log (o rio). Devolve o LSN atribuído.

        `parents` são ULIDs dos episódios que originaram este (arestas de proveniência).
        """
        if isinstance(content, str):
            content = content.encode("utf-8")
        req = pb.AppendRequest(
            agent_id=agent_id,
            session_id=session_id,
            kind=kind,
            content=content,
            attrs={str(k): str(v) for k, v in (attrs or {}).items()},
            parents=list(parents or []),
            hyp=list(hyp or []),
            sph=list(sph or []),
            euc=list(euc or []),
            idempotency_key=str(idempotency_key or ""),
        )
        try:
            deadline = self.timeout if timeout is None else timeout
            response = self._stub.Append(req, metadata=self._md, timeout=deadline)
            if return_metadata:
                return {
                    "lsn": response.lsn,
                    "deduplicated": response.deduplicated,
                    "event_id": response.event_id,
                }
            return response.lsn
        except grpc.RpcError as e:
            raise HeraclitusError(f"Append falhou: {e.details()}") from e

    # ── leitura ──────────────────────────────────────────────────────────
    def query(self, gql, *, as_of=None):
        """Executa GQL/Cypher. `as_of=<lsn>` reconstrói o estado naquele ponto do passado."""
        if as_of is not None and "AS OF" not in gql.upper():
            gql = self._inject_as_of(gql, as_of)
        try:
            resp = self._stub.Query(
                pb.QueryRequest(gql=gql), metadata=self._md, timeout=self.timeout
            )
        except grpc.RpcError as e:
            raise HeraclitusError(f"Query falhou: {e.details()}") from e
        return _loads(resp.json)

    def query_df(self, gql, *, as_of=None):
        """Como `query`, mas devolve um `pandas.DataFrame` (requer pandas)."""
        import pandas as pd

        rows = self.query(gql, as_of=as_of)
        return pd.DataFrame(rows if isinstance(rows, list) else [])

    def provenance(self, ulid):
        """Proveniência: ULIDs dos episódios que originaram `ulid` (arestas `parents`).

        db.provenance("01KV7ZED...")  # -> ['01KV...', '01KV...']
        """
        res = self.query(f'PROVENANCE ("{ulid}")')
        return res if isinstance(res, list) else []

    def recall(self, text, k=10):
        """Recall semântico (ANN no manifold de produto). Devolve as k linhas mais próximas."""
        try:
            resp = self._stub.Recall(
                pb.RecallRequest(text=text, k=int(k)),
                metadata=self._md,
                timeout=self.timeout,
            )
        except grpc.RpcError as e:
            raise HeraclitusError(f"Recall falhou: {e.details()}") from e
        return _loads(resp.json)

    def subscribe(self, from_lsn=0, *, timeout=None):
        """Itera o rio a partir de `from_lsn` (stream). `for ev in db.subscribe(): ...`"""
        try:
            for ev in self._stub.Subscribe(
                pb.SubscribeRequest(from_lsn=int(from_lsn)), metadata=self._md, timeout=timeout
            ):
                yield {"lsn": ev.lsn, "episode": _loads(ev.episode_json)}
        except grpc.RpcError as e:
            raise HeraclitusError(f"Subscribe falhou: {e.details()}") from e

    def head(self):
        """LSN da cabeça do log (último evento)."""
        return self._stub.Snapshot(
            pb.SnapshotRequest(), metadata=self._md, timeout=self.timeout
        ).lsn

    # ── admin / integridade ──────────────────────────────────────────────
    def admin(self, op, arg=""):
        try:
            resp = self._stub.Admin(
                pb.AdminRequest(op=op, arg=arg), metadata=self._md, timeout=self.timeout
            )
            return {"ok": resp.ok, "message": resp.message}
        except grpc.RpcError as e:
            raise HeraclitusError(f"Admin falhou: {e.details()}") from e

    def shred(self, agent_id):
        """Crypto-shredding (§3.10): destrói a chave do agente -> o conteúdo
        cifrado desse agente fica permanentemente ilegível. O log não é mutado.
        Requer encryption_at_rest ativo no servidor."""
        return self.admin(f"shred:{agent_id}")

    def verify(self):
        """Verificação criptográfica de integridade (Árvore de Merkle). {ok, message}."""
        return self.admin("verify")

    def stats(self):
        """Estatísticas do servidor. {ok, message}."""
        return self.admin("stats")

    # ── helpers ──────────────────────────────────────────────────────────
    @staticmethod
    def _inject_as_of(gql, lsn):
        # injeta 'AS OF LSN <n>' antes do RETURN (sintaxe: MATCH ... AS OF LSN n RETURN ...)
        idx = gql.upper().rfind("RETURN")
        clause = f" AS OF LSN {int(lsn)} "
        return (gql.rstrip() + clause) if idx == -1 else (gql[:idx] + clause + gql[idx:])

    def close(self):
        self._channel.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def connect(addr="127.0.0.1:7474", **kw):
    """Atalho: `db = heraclitusdb.connect()`."""
    return Client(addr, **kw)
