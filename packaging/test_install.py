"""Run against the exact packaged binary: no fixture can bypass authentication."""
import importlib.util
import base64
import os
from pathlib import Path
import secrets
import socket
import stat
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request

spec = importlib.util.spec_from_file_location("installer", Path(__file__).with_name("install.py"))
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class InstallationTests(unittest.TestCase):
    def test_invalid_password_cannot_create_instance(self):
        with tempfile.TemporaryDirectory() as root:
            prefix = Path(root) / "instance"
            for bad in ["", "admin", "a" * 32, "x\n" * 32]:
                with self.assertRaises(ValueError):
                    installer.install(prefix, "missing-binary", bad)
                self.assertFalse(prefix.exists())

    def test_password_is_mandatory_hashed_and_reinstall_is_refused(self):
        binary = os.environ.get("INSTALL_TEST_BINARY")
        if not binary:
            self.fail("INSTALL_TEST_BINARY must name the packaged release binary")
        with tempfile.TemporaryDirectory() as root:
            prefix = Path(root) / "instance"
            secret = secrets.token_urlsafe(36)
            config = installer.install(prefix, binary, secret)
            text = config.read_text()
            self.assertNotIn(secret, text)
            self.assertIn('principal = "admin"', text)
            self.assertIn('roles = ["admin"]', text)
            self.assertNotIn("auth_token =", text)
            self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(prefix.stat().st_mode), 0o700)
            with self.assertRaises(ValueError):
                installer.install(prefix, binary, secrets.token_urlsafe(36))
            self.assertEqual(config.read_text(), text)
            # Allocate distinct test ports without touching a running instance.
            with socket.socket() as grpc, socket.socket() as rest:
                grpc.bind(("127.0.0.1", 0))
                rest.bind(("127.0.0.1", 0))
                grpc_port, rest_port = grpc.getsockname()[1], rest.getsockname()[1]
            config.write_text(text.replace("127.0.0.1:7474", f"127.0.0.1:{grpc_port}")
                              .replace("127.0.0.1:7475", f"127.0.0.1:{rest_port}"))
            env = {k:v for k,v in os.environ.items() if not k.upper().startswith("HERACLITUS_")}
            process = subprocess.Popen([str(prefix / "bin" / "heraclitus-server"), str(config)],
                                       env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                url = f"http://127.0.0.1:{rest_port}/stats"
                deadline = time.monotonic() + 30
                while True:
                    self.assertIsNone(process.poll(), "installed server exited")
                    try:
                        urllib.request.urlopen(url, timeout=1).close()
                        self.fail("unauthenticated access unexpectedly succeeded")
                    except urllib.error.HTTPError as error:
                        self.assertEqual(error.code, 401)
                        break
                    except urllib.error.URLError:
                        if time.monotonic() >= deadline:
                            self.fail("installed server did not become ready")
                        time.sleep(0.1)
                for password, expected in [("wrong", 401), (secret, 200)]:
                    header = base64.b64encode(f"admin:{password}".encode()).decode()
                    req = urllib.request.Request(url, headers={"Authorization": f"Basic {header}"})
                    try:
                        with urllib.request.urlopen(req, timeout=3) as response:
                            self.assertEqual(response.status, expected)
                    except urllib.error.HTTPError as error:
                        self.assertEqual(error.code, expected)
            finally:
                process.kill()
                process.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
