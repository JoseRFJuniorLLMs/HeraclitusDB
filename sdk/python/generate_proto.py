"""Regenera os stubs Python a partir do contrato protobuf canônico."""

from pathlib import Path

from grpc_tools import protoc


def main() -> int:
    repo = Path(__file__).resolve().parents[2]
    proto_dir = repo / "crates" / "heraclitus-proto" / "proto"
    output_dir = Path(__file__).resolve().parent / "heraclitusdb"
    proto = proto_dir / "heraclitus.proto"

    result = protoc.main(
        [
            "grpc_tools.protoc",
            f"-I{proto_dir}",
            f"--python_out={output_dir}",
            f"--grpc_python_out={output_dir}",
            str(proto),
        ]
    )
    if result != 0:
        return result

    # grpc_tools gera um import absoluto adequado a módulos soltos. Este SDK é
    # um pacote, portanto o import precisa ser relativo e reproduzível no CI.
    grpc_stub = output_dir / "heraclitus_pb2_grpc.py"
    generated = grpc_stub.read_text(encoding="utf-8")
    generated = generated.replace(
        "import heraclitus_pb2 as heraclitus__pb2",
        "from . import heraclitus_pb2 as heraclitus__pb2",
    )
    grpc_stub.write_text(generated, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
