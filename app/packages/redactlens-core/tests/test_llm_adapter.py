import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from redactlens_core.llm.adapter import (
    DEFAULT_HOST,
    DEFAULT_MODEL,
    OllamaAdapter,
    OllamaModelInfo,
    _is_cloud_model,
    _model_infos,
    _model_matches,
    _model_names,
    _response_text,
)

DEAD_HOST = "http://127.0.0.1:1"  # port 1 refuses connections, no real Ollama needed
LOCAL_DIGEST = "a" * 64


def _local_model(name: str) -> dict[str, object]:
    return {
        "model": name,
        "digest": LOCAL_DIGEST,
        "size": 2_000_000_000,
    }


def _accept_raw_local_details(adapter: OllamaAdapter) -> None:
    adapter._raw_model_details = lambda _model: {}  # type: ignore[method-assign]


def test_available_is_false_for_unreachable_host():
    adapter = OllamaAdapter(host=DEAD_HOST, timeout=2)
    assert adapter.available() is False


def test_judge_returns_none_for_unreachable_host():
    adapter = OllamaAdapter(host=DEAD_HOST, timeout=2)
    assert adapter.judge("Is this sensitive?") is None


def test_default_transport_is_numeric_loopback_without_proxies_or_redirects(monkeypatch):
    captured = {}

    class FakeOllamaClient:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr("redactlens_core.llm.adapter.ollama.Client", FakeOllamaClient)

    OllamaAdapter()

    assert DEFAULT_HOST == "http://127.0.0.1:11434"
    assert captured["host"] == DEFAULT_HOST
    assert captured["trust_env"] is False
    assert captured["follow_redirects"] is False


@pytest.mark.parametrize(
    "host",
    [
        "http://localhost:11434",
        "https://127.0.0.1:11434",
        "http://192.0.2.1:11434",
        "http://user@127.0.0.1:11434",
        "http://127.0.0.1:11434/api",
        "http://127.0.0.1:11434?next=remote",
    ],
)
def test_transport_rejects_every_noncanonical_or_nonloopback_host(host):
    with pytest.raises(ValueError, match="numeric loopback"):
        OllamaAdapter(host=host)


def test_transport_does_not_proxy_or_redirect_prompt_bodies(monkeypatch):
    proxy_hits = []
    redirect_hits = []
    sink_bodies = []

    class QuietHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

    class ProxyHandler(QuietHandler):
        def do_POST(self):
            proxy_hits.append(self.path)
            self.send_response(502)
            self.end_headers()

    class SinkHandler(QuietHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            sink_bodies.append(self.rfile.read(length))
            self.send_response(200)
            self.end_headers()

    proxy = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
    sink = ThreadingHTTPServer(("127.0.0.1", 0), SinkHandler)

    class RedirectHandler(QuietHandler):
        def do_POST(self):
            redirect_hits.append(self.path)
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.send_response(307)
            self.send_header(
                "Location",
                f"http://127.0.0.1:{sink.server_port}/api/generate",
            )
            self.end_headers()

    redirect = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    servers = (proxy, sink, redirect)
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
    for thread in threads:
        thread.start()

    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{proxy.server_port}")
    monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{proxy.server_port}")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)

    marker = "AUDIT_SECRET_MARKER_7f31"
    try:
        adapter = OllamaAdapter(
            host=f"http://127.0.0.1:{redirect.server_port}",
            timeout=2,
        )
        assert adapter.judge(marker) is None
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)

    assert redirect_hits == ["/api/generate"]
    assert proxy_hits == []
    assert sink_bodies == []


def test_raw_show_does_not_use_proxies_or_follow_redirects(monkeypatch):
    proxy_hits = []
    redirect_bodies = []
    sink_bodies = []

    class QuietHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

    class ProxyHandler(QuietHandler):
        def do_POST(self):
            proxy_hits.append(self.path)
            self.send_response(502)
            self.end_headers()

    class SinkHandler(QuietHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            sink_bodies.append(self.rfile.read(length))
            self.send_response(200)
            self.end_headers()

    proxy = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
    sink = ThreadingHTTPServer(("127.0.0.1", 0), SinkHandler)

    class RedirectHandler(QuietHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            redirect_bodies.append(self.rfile.read(length))
            self.send_response(307)
            self.send_header(
                "Location",
                f"http://127.0.0.1:{sink.server_port}/api/show",
            )
            self.end_headers()

    redirect = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    servers = (proxy, sink, redirect)
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
    for thread in threads:
        thread.start()

    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{proxy.server_port}")
    monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{proxy.server_port}")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)

    class FakeInventoryClient:
        def list(self):
            return {"models": [_local_model("qwen3-coder:30b")]}

    try:
        adapter = OllamaAdapter(
            model="qwen3-coder:30b",
            host=f"http://127.0.0.1:{redirect.server_port}",
            timeout=2,
        )
        adapter._client = FakeInventoryClient()
        assert adapter.local_models() == []
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)

    assert redirect_bodies == [b'{"model":"qwen3-coder:30b"}']
    assert proxy_hits == []
    assert sink_bodies == []


def test_judge_returns_none_for_malformed_json_response():
    class FakeClient:
        def generate(self, **kwargs):
            return {"response": "not json at all"}

    adapter = OllamaAdapter(model=DEFAULT_MODEL, host=DEAD_HOST)
    adapter._client = FakeClient()
    assert adapter.judge("Is this sensitive?") is None


def test_judge_parses_well_formed_verdict():
    raw_verdict = '{"is_sensitive": true, "confidence": 0.83, "reason": "looks like an id"}'

    class FakeClient:
        def generate(self, **kwargs):
            return {"response": raw_verdict}

    adapter = OllamaAdapter(model=DEFAULT_MODEL, host=DEAD_HOST)
    adapter._client = FakeClient()
    verdict = adapter.judge("Is this sensitive?")
    assert verdict is not None
    assert verdict.is_sensitive is True
    assert verdict.confidence == 0.83
    assert verdict.reason == "looks like an id"


def test_judge_rejects_wrong_typed_non_finite_and_out_of_range_verdicts():
    invalid_verdicts = [
        '{"is_sensitive": "false", "confidence": 0.8}',
        '{"is_sensitive": 1, "confidence": 0.8}',
        '{"is_sensitive": true, "confidence": "0.8"}',
        '{"is_sensitive": true, "confidence": true}',
        '{"is_sensitive": true, "confidence": NaN}',
        '{"is_sensitive": true, "confidence": Infinity}',
        '{"is_sensitive": true, "confidence": -0.01}',
        '{"is_sensitive": true, "confidence": 1.01}',
    ]

    class FakeClient:
        response = ""

        def generate(self, **kwargs):
            return {"response": self.response}

    adapter = OllamaAdapter(model=DEFAULT_MODEL, host=DEAD_HOST)
    client = FakeClient()
    adapter._client = client

    for raw_verdict in invalid_verdicts:
        client.response = raw_verdict
        assert adapter.judge("Is this sensitive?") is None, raw_verdict


def test_judge_uses_the_configured_reproducibility_options():
    captured = {}

    class FakeClient:
        def generate(self, **kwargs):
            captured.update(kwargs)
            return {"response": '{"is_sensitive": false, "confidence": 0.1}'}

    options = {"temperature": 0, "seed": 9173}
    adapter = OllamaAdapter(model=DEFAULT_MODEL, host=DEAD_HOST, options=options)
    adapter._client = FakeClient()

    assert adapter.judge("Is this sensitive?") is not None
    assert captured["options"] == options


def test_judge_never_logs_the_local_model_prompt(caplog):
    prompt = "private surrounding context with RAW-SECRET-123"

    class FakeClient:
        def generate(self, **kwargs):
            assert kwargs["prompt"] == prompt
            return {"response": '{"is_sensitive": false, "confidence": 0.2, "reason": "no"}'}

    adapter = OllamaAdapter(model=DEFAULT_MODEL, host=DEAD_HOST)
    adapter._client = FakeClient()

    assert adapter.judge(prompt) is not None
    assert prompt not in caplog.text


def test_response_text_handles_dict_and_object_shapes():
    assert _response_text({"response": "hi"}) == "hi"

    class ObjLike:
        response = "hi"

    assert _response_text(ObjLike()) == "hi"


def test_available_is_false_when_server_is_up_but_model_is_missing():
    """Regression test: a reachable Ollama with the wrong/unpulled model
    must count as unavailable, not silently 404 on every judge() call while
    reporting llm_used=True."""

    class FakeClient:
        def list(self):
            return {"models": [_local_model("some-other-model:latest")]}

    adapter = OllamaAdapter(model="llama3.2", host=DEAD_HOST)
    adapter._client = FakeClient()
    _accept_raw_local_details(adapter)
    assert adapter.available() is False


def test_available_is_true_when_configured_model_is_present():
    class FakeClient:
        def list(self):
            return {"models": [_local_model("llama3.2:latest")]}

    adapter = OllamaAdapter(model="llama3.2", host=DEAD_HOST)
    adapter._client = FakeClient()
    _accept_raw_local_details(adapter)
    assert adapter.available() is True


def test_availability_status_distinguishes_service_model_and_ready_states():
    class UnreachableClient:
        def list(self):
            raise ConnectionError("not running")

    class MissingModelClient:
        def list(self):
            return {"models": [_local_model("some-other-model:latest")]}

    class ReadyClient:
        def list(self):
            return {"models": [_local_model("llama3.2:latest")]}

    adapter = OllamaAdapter(model="llama3.2", host=DEAD_HOST)
    _accept_raw_local_details(adapter)

    adapter._client = UnreachableClient()
    assert adapter.availability_status() == "unavailable"
    adapter._client = MissingModelClient()
    assert adapter.availability_status() == "model_missing"
    adapter._client = ReadyClient()
    assert adapter.availability_status() == "ready"


def test_available_model_returns_exact_server_name_including_tag():
    class FakeClient:
        def list(self):
            return {"models": [_local_model("llama3.2:latest")]}

    adapter = OllamaAdapter(model="llama3.2", host=DEAD_HOST)
    adapter._client = FakeClient()
    _accept_raw_local_details(adapter)

    assert adapter.available_model() == "llama3.2:latest"


def test_model_matches_only_allows_latest_for_an_omitted_tag():
    assert _model_matches("llama3.2", "llama3.2:latest")
    assert _model_matches(
        "registry.example:5000/team/llama3.2",
        "registry.example:5000/team/llama3.2:latest",
    )
    assert not _model_matches("llama3.2", "llama3.2")
    assert not _model_matches("llama3.2:latest", "llama3.2")
    assert not _model_matches("llama3.2:1b", "llama3.2:3b")
    assert not _model_matches("llama3.2", "llama3.2:3b")
    assert not _model_matches("llama3.2", "qwen3-coder:30b")
    for malformed in ("llama3.2:", ":latest", " :latest", "llama3.2: latest"):
        assert not _model_matches(malformed, malformed)


def test_model_names_handles_dict_and_object_shapes():
    assert _model_names({"models": [{"model": "a"}, {"name": "b"}]}) == ["a", "b"]

    class ObjModel:
        def __init__(self, name):
            self.model = name

    class ObjResponse:
        models = [ObjModel("a"), ObjModel("b")]

    assert _model_names(ObjResponse()) == ["a", "b"]


def test_available_model_info_retains_exact_tag_and_digest():
    class FakeClient:
        def list(self):
            return {
                "models": [
                    {
                        "model": "llama3.2:latest",
                        "digest": "sha256:" + "a" * 64,
                        "size": 2_000_000_000,
                    }
                ]
            }

    adapter = OllamaAdapter(model="llama3.2", host=DEAD_HOST)
    adapter._client = FakeClient()
    _accept_raw_local_details(adapter)

    info = adapter.available_model_info()

    assert info is not None
    assert info.name == "llama3.2:latest"
    assert info.digest == "sha256:" + "a" * 64
    assert info.size == 2_000_000_000
    assert _model_infos(FakeClient().list()) == [info]


def test_local_models_reports_sizes_and_excludes_cloud_only_tags():
    class FakeClient:
        def list(self):
            return {
                "models": [
                    {
                        "model": "qwen3-coder:30b",
                        "digest": "sha256:" + "a" * 64,
                        "size": 18_600_000_000,
                    },
                    {"model": "gpt-oss:120b-cloud", "size": 1_000},
                    {"model": "glm-4.7:cloud", "size": 1_000},
                ]
            }

    adapter = OllamaAdapter(model="qwen3-coder:30b", host=DEAD_HOST)
    adapter._client = FakeClient()
    _accept_raw_local_details(adapter)

    assert adapter.local_models() == [
        OllamaModelInfo(
            name="qwen3-coder:30b",
            digest="sha256:" + "a" * 64,
            size=18_600_000_000,
        )
    ]
    assert adapter.availability_status() == "ready"


def test_cloud_model_references_are_never_available_for_local_scans():
    assert _is_cloud_model("gpt-oss:120b-cloud")
    assert _is_cloud_model("glm-4.7:cloud")
    assert not _is_cloud_model("qwen3-coder:30b")

    class FakeClient:
        def list(self):
            return {"models": [{"model": "gpt-oss:120b-cloud"}]}

    adapter = OllamaAdapter(model="gpt-oss:120b-cloud", host=DEAD_HOST)
    adapter._client = FakeClient()

    assert adapter.local_models() == []
    assert adapter.available() is False
    assert adapter.availability_status() == "model_missing"


def test_renamed_cloud_and_unverifiable_inventory_entries_are_rejected():
    class FakeClient:
        def list(self):
            return {
                "models": [
                    {
                        "model": "innocent-alias:latest",
                        "digest": LOCAL_DIGEST,
                        "size": 0,
                    },
                    {
                        "model": "missing-digest:latest",
                        "size": 2_000_000_000,
                    },
                    {
                        "model": "malformed-digest:latest",
                        "digest": "not-a-content-digest",
                        "size": 2_000_000_000,
                    },
                ]
            }

    adapter = OllamaAdapter(model="innocent-alias:latest", host=DEAD_HOST)
    adapter._client = FakeClient()

    assert adapter.local_models() == []
    assert adapter.available() is False


@pytest.mark.parametrize(
    "details",
    [
        {"remote_host": "https://ollama.com:443", "remote_model": "gpt-oss:120b"},
        {"remote_host": "https://ollama.com:443"},
        {"remote_model": "gpt-oss:120b"},
    ],
)
def test_raw_show_rejects_remote_models_even_with_local_looking_inventory(details):
    class FakeClient:
        def list(self):
            return {"models": [_local_model("innocent-alias:latest")]}

    adapter = OllamaAdapter(model="innocent-alias:latest", host=DEAD_HOST)
    adapter._client = FakeClient()
    adapter._raw_model_details = lambda _model: details  # type: ignore[method-assign]

    assert adapter.local_models() == []
    assert adapter.available() is False


@pytest.mark.parametrize("details", [None, [], "not an object"])
def test_raw_show_fails_closed_for_missing_or_malformed_model_details(details):
    class FakeClient:
        def list(self):
            return {"models": [_local_model("qwen3-coder:30b")]}

    adapter = OllamaAdapter(model="qwen3-coder:30b", host=DEAD_HOST)
    adapter._client = FakeClient()
    adapter._raw_model_details = lambda _model: details  # type: ignore[method-assign,return-value]

    assert adapter.local_models() == []
    assert adapter.available() is False
