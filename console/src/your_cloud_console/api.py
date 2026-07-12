from __future__ import annotations

from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import socketserver
import signal
from typing import Any
from urllib.parse import urlsplit

from . import __version__
from .errors import ConsoleError
from .model import load_declaration


class UnixHTTPServer(socketserver.UnixStreamServer):
    allow_reuse_address = True

    def __init__(self, socket_path: Path, declaration_path: Path):
        self.socket_path = socket_path
        self.declaration_path = declaration_path
        super().__init__(str(socket_path), ApiHandler)

    def server_bind(self) -> None:
        super().server_bind()
        os.chmod(self.socket_path, 0o600)


class ApiHandler(BaseHTTPRequestHandler):
    server: UnixHTTPServer

    def address_string(self) -> str:
        return "local-unix-socket"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        try:
            declaration = load_declaration(self.server.declaration_path)
            if path == "/v1/status":
                self._json(
                    200,
                    {
                        "api_version": "v1",
                        "console_version": __version__,
                        "schema_version": declaration.schema_version,
                        "transport": "unix-socket",
                        "mutation_capable": False,
                        "milestone": "P2",
                    },
                )
            elif path == "/v1/declaration":
                self._json(200, declaration.to_dict())
            elif path == "/v1/machines":
                self._json(200, {"machines": [machine.__dict__ for machine in declaration.machines]})
            elif path == "/v1/infrastructures":
                self._json(
                    200,
                    {"infrastructures": [item.__dict__ for item in declaration.infrastructures]},
                )
            else:
                self._json(404, {"error": "route inconnue", "path": path})
        except ConsoleError as error:
            self._json(422, {"error": str(error)})

    def do_POST(self) -> None:
        self._json(405, {"error": "P2 expose uniquement une API locale en lecture seule"})


def serve(socket_path: Path, declaration_path: Path) -> None:
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    if socket_path.exists() or socket_path.is_symlink():
        mode = socket_path.lstat().st_mode
        if not socket_path.is_socket():
            raise ConsoleError(f"refus de remplacer un chemin non-socket : {socket_path} (mode {mode:o})")
        socket_path.unlink()
    server = UnixHTTPServer(socket_path, declaration_path)
    previous_sigterm = signal.getsignal(signal.SIGTERM)

    def terminate(_signum: int, _frame: Any) -> None:
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, terminate)
    try:
        server.serve_forever()
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm)
        server.server_close()
        try:
            if socket_path.is_socket():
                socket_path.unlink()
        except FileNotFoundError:
            pass
