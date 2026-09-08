#!/usr/bin/env python3
"""Install a new, loopback-only Linux RC instance with mandatory admin setup.

Uses the existing RBAC token verifier, NOT a password KDF. Choose a random
32+ character credential from a password manager, not a reused human password.
No services are started, no existing installation is overwritten.
"""
import argparse
import getpass
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys


def validate_secret(secret):
    if not 32 <= len(secret) <= 128 or any(not 32 <= ord(c) <= 126 for c in secret):
        raise ValueError("A senha/token admin deve ter 32 a 128 caracteres ASCII imprimíveis.")
    if len(set(secret)) < 12:
        raise ValueError("Use uma credencial aleatória de um gestor de senhas; não use repetições.")


def install(prefix, binary, secret):
    validate_secret(secret)
    prefix = Path(prefix).absolute()
    binary = Path(binary).resolve(strict=True)
    if prefix.exists() or prefix.is_symlink():
        raise ValueError("Destino já existe; instalação recusada sem alterar arquivos.")
    # Never forward inherited data/auth overrides to utilities or installed server.
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("HERACLITUS_")}
    result = subprocess.run(
        [str(binary), "--credential-hash-stdin"], input=secret.encode("ascii"),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=30,
    )
    digest = result.stdout.decode("ascii", errors="replace").strip()
    if result.returncode or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("O binário não conseguiu gerar a credencial; nada foi instalado.")
    prefix.mkdir(mode=0o700)  # parents must already exist; never follow an existing destination
    (prefix / "data").mkdir(mode=0o700)
    (prefix / "bin").mkdir(mode=0o700)
    target = prefix / "bin" / "heraclitus-server"
    shutil.copyfile(binary, target)
    target.chmod(0o700)
    config = (
        f'data_dir = {json.dumps(str(prefix / "data"), ensure_ascii=False)}\n'
        'grpc_addr = "127.0.0.1:7474"\nrest_addr = "127.0.0.1:7475"\n'
        'encryption_at_rest = true\nfsync = { mode = "always" }\n'
        '[[access_credentials]]\nprincipal = "admin"\nroles = ["admin"]\n'
        f'token_blake3 = "{digest}"\n'
    )
    config_path = prefix / "heraclitus.toml"
    with config_path.open("x", encoding="utf-8") as out:
        out.write(config)
    config_path.chmod(0o600)
    launcher = prefix / "start.py"
    with launcher.open("x", encoding="utf-8") as out:
        out.write(
            '#!/usr/bin/env python3\nimport os\nfrom pathlib import Path\n'
            'root = Path(__file__).resolve().parent\n'
            'env = {k:v for k,v in os.environ.items() if not k.upper().startswith("HERACLITUS_")}\n'
            'binary = str(root / "bin" / "heraclitus-server")\n'
            'os.execve(binary, [binary, str(root / "heraclitus.toml")], env)\n'
        )
    launcher.chmod(0o700)
    return config_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", required=True, help="new instance directory (must not exist)")
    parser.add_argument("--password-stdin", action="store_true", help="automation: read secret from stdin, never argv")
    args = parser.parse_args()
    if os.name != "posix":
        parser.error("Este instalador é para o pacote Linux.")
    if args.password_stdin:
        secret = sys.stdin.read(130).removesuffix("\n")
    else:
        if not sys.stdin.isatty():
            parser.error("Instalação requer senha admin; use terminal ou --password-stdin.")
        print("Defina a senha/token admin: use 32+ caracteres aleatórios de um gestor de senhas.")
        secret = getpass.getpass("Senha admin (não será exibida): ")
        if secret != getpass.getpass("Confirme a senha admin: "):
            parser.error("As senhas não coincidem; nada foi instalado.")
    try:
        config = install(args.prefix, Path(__file__).resolve().parent / "bin" / "heraclitus-server", secret)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    print(f"Instalação criada em {config.parent}. Utilizador: admin. Nenhum serviço foi iniciado.")
    print(f"Arranque: python3 {shlex.quote(str(config.parent / 'start.py'))}")
    print("REST: Basic admin + senha/token; gRPC: Bearer com a mesma credencial. Apenas loopback.")


if __name__ == "__main__":
    main()
