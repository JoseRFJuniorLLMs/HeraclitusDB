from types import SimpleNamespace

import pytest

from heraclitusdb import Client, HeraclitusError
from heraclitusdb import client as client_module


class FakeChannel:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class FakeStub:
    def __init__(self):
        self.append_calls = []
        self.query_calls = []
        self.admin_error = None

    def Append(self, request, *, metadata, timeout):
        self.append_calls.append((request, metadata, timeout))
        return SimpleNamespace(lsn=41, deduplicated=True, event_id="01TEST")

    def Query(self, request, *, metadata, timeout):
        self.query_calls.append((request, metadata, timeout))
        return SimpleNamespace(json='[{"ok": true}]')

    def Admin(self, request, *, metadata, timeout):
        if self.admin_error:
            raise self.admin_error
        return SimpleNamespace(ok=True, message="ok")


class DeniedRpcError(client_module.grpc.RpcError):
    def details(self):
        return "principal sem papel Auditor"


@pytest.fixture
def fake_transport(monkeypatch):
    channel = FakeChannel()
    stub = FakeStub()
    monkeypatch.setattr(client_module.grpc, "insecure_channel", lambda *args, **kwargs: channel)
    monkeypatch.setattr(client_module.rpc, "HeraclitusStub", lambda _: stub)
    return channel, stub


def test_append_forwards_idempotency_auth_and_deadline(fake_transport):
    _, stub = fake_transport
    client = Client(token="writer-secret", timeout=12)

    result = client.append(
        "Observation",
        "conteúdo",
        agent_id="forge:client-1",
        attrs={"source": "syslog"},
        idempotency_key="source-17",
        return_metadata=True,
    )

    assert result == {"lsn": 41, "deduplicated": True, "event_id": "01TEST"}
    request, metadata, timeout = stub.append_calls[0]
    assert request.content == "conteúdo".encode()
    assert request.idempotency_key == "source-17"
    assert request.attrs == {"source": "syslog"}
    assert metadata == [("authorization", "Bearer writer-secret")]
    assert timeout == 12


def test_query_injects_as_of_without_changing_existing_clause(fake_transport):
    _, stub = fake_transport
    client = Client()

    assert client.query("MATCH (n) RETURN n", as_of=99) == [{"ok": True}]
    assert stub.query_calls[0][0].gql == "MATCH (n)  AS OF LSN 99 RETURN n"

    client.query("MATCH (n) AS OF LSN 7 RETURN n", as_of=99)
    assert stub.query_calls[1][0].gql == "MATCH (n) AS OF LSN 7 RETURN n"


def test_mtls_requires_key_and_certificate_together(monkeypatch):
    monkeypatch.setattr(client_module.rpc, "HeraclitusStub", lambda _: FakeStub())

    with pytest.raises(ValueError, match="fornecidos juntos"):
        Client(tls=True, private_key=b"key")


def test_close_closes_underlying_channel(fake_transport):
    channel, _ = fake_transport
    client = Client()
    client.close()
    assert channel.closed


def test_token_file_is_used_when_environment_token_is_absent(fake_transport, monkeypatch, tmp_path):
    _, stub = fake_transport
    token_file = tmp_path / "writer.token"
    token_file.write_text("segredo-forge-writer", encoding="ascii")
    monkeypatch.delenv("HERACLITUS_TOKEN", raising=False)
    monkeypatch.setenv("HERACLITUS_TOKEN_FILE", str(token_file))

    client = Client()
    client.append("Observation", "evento")
    assert stub.append_calls[0][1] == [("authorization", "Bearer segredo-forge-writer")]


def test_admin_wraps_grpc_failures_in_sdk_error(fake_transport):
    _, stub = fake_transport
    stub.admin_error = DeniedRpcError()
    client = Client()

    with pytest.raises(HeraclitusError, match="principal sem papel Auditor"):
        client.verify()
