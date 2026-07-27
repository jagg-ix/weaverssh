import asyncio
from pathlib import Path

from tools.verification import local_context_mcp_service as lcms


async def _dummy_app(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


def _run_middleware(headers):
    messages = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    middleware = lcms.BearerTokenMiddleware(_dummy_app, "secret-token")
    scope = {"type": "http", "headers": headers, "path": "/mcp"}
    asyncio.run(middleware(scope, receive, send))
    return messages


def _status(messages):
    return next(m["status"] for m in messages if m["type"] == "http.response.start")


def test_bearer_token_middleware_rejects_missing_header():
    assert _status(_run_middleware([])) == 401


def test_bearer_token_middleware_rejects_wrong_header():
    assert _status(_run_middleware([(b"authorization", b"Bearer wrong")])) == 401


def test_bearer_token_middleware_accepts_matching_header():
    assert _status(_run_middleware([(b"authorization", b"Bearer secret-token")])) == 200


def test_read_auth_token_prefers_explicit_token(tmp_path: Path):
    token_file = tmp_path / "token"
    token_file.write_text("from-file\n", encoding="utf-8")
    assert lcms._read_auth_token(token="explicit", token_file=token_file) == "explicit"
    assert lcms._read_auth_token(token="", token_file=token_file) == "from-file"

class _FakeStarletteApp:
    def __init__(self):
        self.middlewares = []

    def add_middleware(self, middleware, **kwargs):
        self.middlewares.append((middleware, kwargs))


class _FakeFastMCP:
    def __init__(self):
        self.run_calls = []
        self.http_app = _FakeStarletteApp()
        self.sse_server_app = _FakeStarletteApp()

    def run(self, **kwargs):
        self.run_calls.append(kwargs)

    def streamable_http_app(self):
        return self.http_app

    def sse_app(self):
        return self.sse_server_app


def test_run_listener_uses_uvicorn_for_tls_without_auth(monkeypatch):
    captured = {}

    class _FakeUvicorn:
        @staticmethod
        def run(app, **kwargs):
            captured["app"] = app
            captured["kwargs"] = kwargs

    monkeypatch.setitem(__import__("sys").modules, "uvicorn", _FakeUvicorn)
    app = _FakeFastMCP()

    lcms._run_listener_with_optional_auth(
        app,
        transport="streamable-http",
        host="127.0.0.1",
        port=9443,
        auth_token="",
        tls_cert_file="cert.pem",
        tls_key_file="key.pem",
    )

    assert app.run_calls == []
    assert captured["app"] is app.http_app
    assert captured["kwargs"]["ssl_certfile"] == "cert.pem"
    assert captured["kwargs"]["ssl_keyfile"] == "key.pem"
    assert app.http_app.middlewares == []


def test_run_listener_rejects_partial_tls_configuration():
    app = _FakeFastMCP()
    try:
        lcms._run_listener_with_optional_auth(
            app,
            transport="streamable-http",
            host="127.0.0.1",
            port=9443,
            auth_token="",
            tls_cert_file="cert.pem",
            tls_key_file="",
        )
    except SystemExit as exc:
        assert "TLS requires both" in str(exc)
    else:
        raise AssertionError("partial TLS configuration should fail closed")
