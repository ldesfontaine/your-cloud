import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest

from your_cloud_console.api import UnixHTTPServer
from your_cloud_console.model import empty_declaration, save_declaration


def request(socket_path: Path, method: str, path: str):
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.connect(str(socket_path))
        client.sendall(f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode())
        chunks = []
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        client.close()
    headers, body = b"".join(chunks).split(b"\r\n\r\n", 1)
    return headers.decode(), json.loads(body)


class ApiTests(unittest.TestCase):
    def test_status_is_local_and_read_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            declaration = root / "declaration.json"
            socket_path = root / "console.sock"
            save_declaration(declaration, empty_declaration())
            server = UnixHTTPServer(socket_path, declaration)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                headers, payload = request(socket_path, "GET", "/v1/status")
                self.assertIn("200 OK", headers)
                self.assertEqual(payload["transport"], "unix-socket")
                self.assertFalse(payload["mutation_capable"])
                headers, payload = request(socket_path, "POST", "/v1/status")
                self.assertIn("405 Method Not Allowed", headers)
                self.assertIn("lecture seule", payload["error"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
