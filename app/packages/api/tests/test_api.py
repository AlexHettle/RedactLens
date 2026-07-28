import io
import json
import logging
import os
import threading
import time
import zipfile
from pathlib import Path

import pytest
import redactlens_api.main as main_module
from fastapi import FastAPI
from fastapi.testclient import TestClient
from redactlens_api.main import app
from redactlens_api.security import (
    AUTH_HEADER,
    CONTENT_SECURITY_POLICY,
    DEFAULT_MAX_REQUEST_BYTES,
)
from redactlens_api.sessions import ScanSessionStore
from redactlens_core import atomic
from redactlens_core.llm.adapter import OllamaModelInfo
from redactlens_core.models import ScanRequest, ScanResult
from redactlens_core.progress import ScanCancelled, ScanEvent

client = TestClient(app, base_url="http://127.0.0.1:8000")
launch_token = client.get("/launch-session").json()["token"]
client.headers.update({AUTH_HEADER: launch_token})


def test_frontend_files_are_not_cached_by_the_desktop_webview(tmp_path: Path) -> None:
    (tmp_path / "index.html").write_text("<h1>Current UI</h1>", encoding="utf-8")
    static_app = FastAPI()
    static_app.mount(
        "/",
        main_module.FrontendStaticFiles(directory=tmp_path, html=True),
    )

    response = TestClient(static_app).get("/")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"


def test_appearance_theme_is_saved_for_the_next_native_splash(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    theme_file = tmp_path / "appearance-theme"
    monkeypatch.setenv("REDACTLENS_APPEARANCE_THEME_FILE", str(theme_file))

    response = client.put("/appearance/theme", json={"theme": "dark"})

    assert response.status_code == 204
    assert theme_file.read_text(encoding="ascii") == "dark"
    assert client.put("/appearance/theme", json={"theme": "sepia"}).status_code == 422


class FakeClock:
    def __init__(self, value: float = 1_700_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


@pytest.fixture(autouse=True)
def isolated_session_store(monkeypatch):
    clock = FakeClock()
    store = ScanSessionStore(idle_timeout_seconds=60, clock=clock)
    monkeypatch.setattr(main_module, "session_store", store)
    yield clock, store
    store.clear()


def _create_scan(path: Path, **overrides):
    body = {"paths": [str(path)], **overrides}
    response = client.post("/scans", json=body)
    assert response.status_code == 201, response.text
    created = response.json()
    assert created["state"] in {
        "pending",
        "discovering",
        "scanning",
        "refining",
        "complete",
    }
    return _wait_for_terminal(created["scan_id"])


def _wait_for_terminal(scan_id: str, timeout: float = 3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = client.get(f"/scans/{scan_id}")
        assert response.status_code == 200, response.text
        body = response.json()
        if body["state"] in {"complete", "cancelled", "failed", "timed_out"}:
            return body
        time.sleep(0.01)
    raise AssertionError(f"scan {scan_id} did not reach a terminal state")


def _error_code(response) -> str:
    return response.json()["error"]["code"]


def _incomplete_action_responses(scan_id: str):
    return [
        client.get(f"/scans/{scan_id}/remediation"),
        client.put(
            f"/scans/{scan_id}/remediation",
            json={
                "plan_revision": 0,
                "included_finding_ids": ["untrusted-finding"],
                "ignored_finding_ids": [],
            },
        ),
        client.post(
            f"/scans/{scan_id}/remediation/generate",
            json={"plan_revision": 0},
        ),
        client.post(
            f"/scans/{scan_id}/reveal-findings",
            json={"finding_ids": ["untrusted-finding"]},
        ),
        client.post(
            f"/scans/{scan_id}/open-file",
            json={"finding_id": "untrusted-finding"},
        ),
        client.post(
            f"/scans/{scan_id}/open-output",
            json={"finding_id": "untrusted-finding"},
        ),
    ]


def _sse_events(response) -> list[dict]:
    return [
        json.loads(line.removeprefix("data: "))
        for line in response.text.splitlines()
        if line.startswith("data: ")
    ]


def _plan_revision(scan_id: str) -> int:
    return client.get(f"/scans/{scan_id}/remediation").json()["plan_revision"]


def _update_plan(
    scan_id: str,
    included: list[str],
    ignored: list[str] | None = None,
    *,
    plan_revision: int | None = None,
):
    return client.put(
        f"/scans/{scan_id}/remediation",
        json={
            "plan_revision": (_plan_revision(scan_id) if plan_revision is None else plan_revision),
            "included_finding_ids": included,
            "ignored_finding_ids": ignored or [],
        },
    )


def _generate(
    scan_id: str,
    *,
    plan_revision: int | None = None,
    output_mode: str = "copy",
):
    return client.post(
        f"/scans/{scan_id}/remediation/generate",
        json={
            "plan_revision": (_plan_revision(scan_id) if plan_revision is None else plan_revision),
            "output_mode": output_mode,
        },
    )


def _word_document(text: str) -> bytes:
    document = (
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>"
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("word/document.xml", document)
    return buffer.getvalue()


def _pdf_document(text: str) -> bytes:
    """Create a minimal one-page digital PDF with a correct xref table."""
    content = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n%s\nendstream" % (len(content), content),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    output = io.BytesIO()
    output.write(b"%PDF-1.4\n")
    offsets = []
    for number, obj in enumerate(objects, start=1):
        offsets.append(output.tell())
        output.write(b"%d 0 obj\n%s\nendobj\n" % (number, obj))
    xref_at = output.tell()
    output.write(b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1))
    for offset in offsets:
        output.write(b"%010d 00000 n \n" % offset)
    output.write(
        b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n"
        % (len(objects) + 1, xref_at)
    )
    return output.getvalue()


def test_health_reports_ok_and_detailed_ollama_status(monkeypatch):
    adapter_timeouts = []

    class FakeOllamaAdapter:
        model = "qwen3-coder:30b"

        def __init__(self, *, timeout):
            adapter_timeouts.append(timeout)

        def local_models(self):
            return [
                OllamaModelInfo(
                    name="llama3.2:latest",
                    digest="sha256:" + "a" * 64,
                    size=2_000_000_000,
                )
            ]

        def matching_model_info(self, models):
            return next((model for model in models if model.name == self.model), None)

    monkeypatch.setattr(main_module, "OllamaAdapter", FakeOllamaAdapter)
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["ollama_available"] is False
    assert body["ollama_status"] == "model_missing"
    assert body["ollama_model"] == "qwen3-coder:30b"
    assert body["ollama_models"] == [{"name": "llama3.2:latest", "size_bytes": 2_000_000_000}]
    assert adapter_timeouts == [2.0]


def test_ai_scan_rejects_a_model_that_is_not_installed_locally(monkeypatch, tmp_path):
    class MissingModelAdapter:
        def __init__(self, *, model):
            self.model = model

        def local_models(self):
            return []

        def matching_model_info(self, _models):
            return None

    monkeypatch.setattr(main_module, "OllamaAdapter", MissingModelAdapter)

    response = client.post(
        "/scans",
        json={
            "paths": [str(tmp_path)],
            "use_llm": True,
            "ollama_model": "gpt-oss:120b-cloud",
        },
    )

    assert response.status_code == 409
    assert _error_code(response) == "ollama_model_unavailable"
    assert "not installed as a local model" in response.json()["error"]["message"]
    assert "Advanced scan options" in response.json()["error"]["message"]


def test_ai_scan_resolves_and_retains_the_selected_local_model(
    monkeypatch, tmp_path, isolated_session_store
):
    _clock, store = isolated_session_store
    local_model = OllamaModelInfo(
        name="llama3.2:3b",
        digest="sha256:" + "b" * 64,
        size=2_100_000_000,
    )

    class LocalModelAdapter:
        def __init__(self, *, model):
            self.model = model

        def local_models(self):
            return [local_model]

        def matching_model_info(self, models):
            return next((model for model in models if model.name == self.model), None)

    monkeypatch.setattr(main_module, "OllamaAdapter", LocalModelAdapter)
    monkeypatch.setattr(store, "start_job", lambda *_args, **_kwargs: None)

    response = client.post(
        "/scans",
        json={
            "paths": [str(tmp_path)],
            "use_llm": True,
            "ollama_model": "llama3.2:3b",
        },
    )

    assert response.status_code == 201
    session = store.get(response.json()["scan_id"])
    assert session.request is not None
    assert session.request.ollama_model == "llama3.2:3b"


def test_mutating_request_requires_the_per_launch_token(tmp_path):
    untrusted = TestClient(app, base_url="http://127.0.0.1:8000")

    response = untrusted.post("/scans", json={"paths": [str(tmp_path)]})

    assert response.status_code == 403
    assert _error_code(response) == "invalid_launch_token"
    assert launch_token not in response.text


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("POST", "/pick-path?kind=folder", None),
        ("POST", "/scans", {"paths": ["C:/safe"]}),
        (
            "PUT",
            "/scans/not-a-session/remediation",
            {
                "plan_revision": 0,
                "included_finding_ids": [],
                "ignored_finding_ids": [],
            },
        ),
        (
            "POST",
            "/scans/not-a-session/remediation/generate",
            {"plan_revision": 0},
        ),
        (
            "POST",
            "/scans/not-a-session/reveal-findings",
            {"finding_ids": ["finding-1"]},
        ),
        ("POST", "/scans/not-a-session/open-file", {"finding_id": "finding-1"}),
        ("POST", "/scans/not-a-session/open-output", {"finding_id": "finding-1"}),
        ("DELETE", "/scans/not-a-session", None),
    ],
)
def test_every_side_effect_route_requires_the_launch_token(method, path, body):
    untrusted = TestClient(app, base_url="http://127.0.0.1:8000")

    response = untrusted.request(method, path, json=body)

    assert response.status_code == 403
    assert response.json() == {
        "error": {
            "code": "invalid_launch_token",
            "message": "Reload RedactLens to establish a valid local session.",
        }
    }


def test_non_ascii_launch_token_is_rejected_without_an_internal_error():
    untrusted = TestClient(app, base_url="http://127.0.0.1:8000")

    response = untrusted.post(
        "/scans",
        json={"paths": ["C:/safe"]},
        headers=[(AUTH_HEADER.encode("ascii"), b"\xff")],
    )

    assert response.status_code == 403
    assert _error_code(response) == "invalid_launch_token"


def test_launch_token_is_ephemeral_and_never_cacheable():
    response = client.get("/launch-session")

    assert response.status_code == 200
    assert response.json() == {"token": launch_token}
    assert len(launch_token) >= 40
    assert response.headers["cache-control"] == "no-store"


def test_launch_security_repr_does_not_disclose_the_capability():
    assert launch_token not in repr(main_module.launch_security)
    assert launch_token not in repr(app.user_middleware)


def test_untrusted_browser_cannot_trigger_a_redacted_file_write(tmp_path):
    original = tmp_path / "secrets.py"
    original.write_text('ssn = "123-45-6789"\n')
    scan = _create_scan(original)
    _update_plan(scan["scan_id"], [scan["findings"][0]["id"]])
    untrusted = TestClient(app, base_url="http://127.0.0.1:8000")

    response = untrusted.post(f"/scans/{scan['scan_id']}/remediation/generate")

    assert response.status_code == 403
    assert _error_code(response) == "invalid_launch_token"
    assert not (tmp_path / "secrets-auto-redacted-copy.py").exists()


def test_host_and_origin_checks_reject_forged_browser_requests(tmp_path):
    bad_host = client.post(
        "/scans",
        json={"paths": [str(tmp_path)]},
        headers={"Host": "attacker.example:8000"},
    )
    bad_origin = client.post(
        "/scans",
        json={"paths": [str(tmp_path)]},
        headers={"Origin": "https://attacker.example"},
    )
    cross_site = client.get("/launch-session", headers={"Sec-Fetch-Site": "cross-site"})

    assert bad_host.status_code == 400
    assert _error_code(bad_host) == "invalid_host"
    assert bad_origin.status_code == 403
    assert _error_code(bad_origin) == "invalid_origin"
    assert cross_site.status_code == 403
    assert _error_code(cross_site) == "invalid_origin"


@pytest.mark.parametrize(
    "host",
    [
        "localhost:8000",
        "LOCALHOST:8001",
        "localhost:8010",
        "127.0.0.1:8005",
        "[::1]:8007",
    ],
)
def test_canonical_loopback_host_authorities_are_allowed(host):
    headers = {"Host": host}
    if host.startswith("["):
        headers["Origin"] = "http://[::1]:8007"

    response = client.get("/launch-session", headers=headers)

    assert response.status_code == 200
    assert response.json() == {"token": launch_token}


@pytest.mark.parametrize(
    "host",
    [
        "evil@localhost:8000",
        "localhost:8000?ignored",
        "localhost:8000#ignored",
        "localhost:8000/path",
        "localhost:08000",
        "localhost:8000:8001",
        "localhost:7999",
        "localhost:8011",
        "localhost",
        "::1:8000",
        "[::1]",
        "[::1]:8000?ignored",
    ],
)
def test_malformed_or_out_of_range_host_authorities_are_rejected(host):
    response = client.get("/launch-session", headers={"Host": host})

    assert response.status_code == 400
    assert _error_code(response) == "invalid_host"


def test_allowed_development_origin_can_use_the_authorized_picker(monkeypatch):
    monkeypatch.setattr("redactlens_api.main.pick_path", lambda kind: "")

    response = client.post(
        "/pick-path?kind=folder",
        headers={"Origin": "http://localhost:5173"},
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_get_pick_path_never_opens_the_native_dialog(monkeypatch):
    def forbidden_picker(_kind):
        raise AssertionError("GET must not open a native picker")

    monkeypatch.setattr("redactlens_api.main.pick_path", forbidden_picker)

    response = client.get("/pick-path?kind=folder")

    assert response.status_code in {404, 405}
    assert _error_code(response) in {"not_found", "method_not_allowed"}


def test_allowed_development_preflight_is_narrow_and_hostile_origin_is_denied():
    preflight_headers = {
        "Origin": "http://localhost:5173",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": f"content-type,{AUTH_HEADER}",
    }

    allowed = client.options("/pick-path", headers=preflight_headers)
    hostile = client.options(
        "/pick-path",
        headers={**preflight_headers, "Origin": "https://attacker.example"},
    )

    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "POST" in allowed.headers["access-control-allow-methods"]
    assert AUTH_HEADER.lower() in allowed.headers["access-control-allow-headers"].lower()
    assert allowed.headers["cache-control"] == "no-store"
    assert allowed.headers["x-content-type-options"] == "nosniff"
    assert allowed.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    assert allowed.headers["x-frame-options"] == "DENY"
    assert hostile.status_code == 403
    assert hostile.json() == {
        "error": {
            "code": "invalid_origin",
            "message": "This browser origin is not allowed to control RedactLens.",
        }
    }
    assert hostile.headers["content-type"].startswith("application/json")
    assert hostile.headers["cache-control"] == "no-store"
    assert hostile.headers["x-content-type-options"] == "nosniff"
    assert "access-control-allow-origin" not in hostile.headers


def test_invalid_host_preflight_is_rejected_before_cors_can_answer():
    response = client.options(
        "/pick-path",
        headers={
            "Host": "attacker.example:8000",
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": f"content-type,{AUTH_HEADER}",
        },
    )

    assert response.status_code == 400
    assert response.json() == {
        "error": {
            "code": "invalid_host",
            "message": "RedactLens only accepts loopback requests.",
        }
    }
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    assert response.headers["x-frame-options"] == "DENY"
    assert "access-control-allow-origin" not in response.headers


def test_allowed_development_origin_can_read_a_launch_token_error():
    untrusted = TestClient(app, base_url="http://127.0.0.1:8000")

    response = untrusted.post(
        "/pick-path?kind=folder",
        headers={"Origin": "http://localhost:5173"},
    )

    assert response.status_code == 403
    assert _error_code(response) == "invalid_launch_token"
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert response.headers["vary"] == "Origin"


def test_trusted_responses_cannot_be_framed():
    response = client.get("/launch-session")
    rejected = client.get("/launch-session", headers={"Host": "attacker.example:8000"})

    assert response.status_code == 200
    assert response.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    assert response.headers["x-frame-options"] == "DENY"
    assert rejected.status_code == 400
    assert rejected.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    assert rejected.headers["x-frame-options"] == "DENY"


def test_request_body_limit_rejects_oversized_content_before_parsing():
    response = client.post(
        "/scans",
        content=b"x" * (DEFAULT_MAX_REQUEST_BYTES + 1),
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert _error_code(response) == "request_too_large"


def test_streamed_request_body_is_bounded_without_a_content_length():
    chunks = iter([b"x" * 100_000, b"y" * 100_000, b"z" * 100_000])

    response = client.post(
        "/scans",
        content=chunks,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert _error_code(response) == "request_too_large"


def test_validation_errors_do_not_echo_sensitive_input(tmp_path):
    raw_target = "TOP-SECRET-VALUE" * 600

    response = client.post(
        "/scans",
        json={
            "paths": [str(tmp_path)],
            "user_targets": [{"kind": "literal", "value": raw_target, "category": "custom"}],
        },
    )

    assert response.status_code == 422
    assert _error_code(response) == "invalid_request"
    assert raw_target not in response.text
    assert "input" not in response.text
    assert response.json()["error"]["message"] == (
        "The request is invalid. Check: user_targets.value."
    )


def test_json_parser_offsets_are_not_reported_as_field_names():
    response = client.post(
        "/scans",
        content=b'{"paths": [}',
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 422
    assert response.json() == {
        "error": {
            "code": "invalid_request",
            "message": "The request is invalid.",
        }
    }


def test_validation_errors_do_not_echo_undeclared_client_keys(tmp_path):
    hostile_top_level_key = "UNTRUSTED-TOP-LEVEL-KEY"
    hostile_nested_key = "UNTRUSTED-NESTED-KEY"

    response = client.post(
        "/scans",
        json={
            "paths": [str(tmp_path)],
            hostile_top_level_key: "value",
            "user_targets": [
                {
                    "kind": "literal",
                    "value": "example",
                    "category": "custom",
                    hostile_nested_key: "value",
                }
            ],
        },
    )

    assert response.status_code == 422
    assert _error_code(response) == "invalid_request"
    assert hostile_top_level_key not in response.text
    assert hostile_nested_key not in response.text


def test_scan_and_remediation_collection_limits_are_enforced():
    too_many_paths = client.post(
        "/scans",
        json={"paths": [f"C:/safe/path-{index}" for index in range(65)]},
    )
    at_findings_limit = client.put(
        "/scans/not-a-session/remediation",
        json={
            "plan_revision": 0,
            "included_finding_ids": [f"finding-{index}" for index in range(4_999)],
            "ignored_finding_ids": ["last-allowed"],
        },
    )
    too_many_findings = client.put(
        "/scans/not-a-session/remediation",
        json={
            "plan_revision": 0,
            "included_finding_ids": [f"finding-{index}" for index in range(5_000)],
            "ignored_finding_ids": ["one-too-many"],
        },
    )
    too_many_reveals = client.post(
        "/scans/not-a-session/reveal-findings",
        json={"finding_ids": [f"finding-{index}" for index in range(251)]},
    )

    assert too_many_paths.status_code == 422
    assert _error_code(too_many_paths) == "invalid_request"
    assert at_findings_limit.status_code == 410
    assert _error_code(at_findings_limit) == "scan_expired"
    assert too_many_findings.status_code == 422
    assert _error_code(too_many_findings) == "invalid_request"
    assert too_many_findings.json()["error"]["message"] == "The request is invalid."
    assert too_many_reveals.status_code == 422
    assert _error_code(too_many_reveals) == "invalid_request"


def test_category_and_user_target_collection_limits_are_enforced(tmp_path):
    too_many_categories = client.post(
        "/scans",
        json={
            "paths": [str(tmp_path)],
            "categories": [f"category-{index}" for index in range(33)],
        },
    )
    too_many_targets = client.post(
        "/scans",
        json={
            "paths": [str(tmp_path)],
            "user_targets": [
                {"kind": "literal", "value": f"target-{index}", "category": "custom"}
                for index in range(101)
            ],
        },
    )

    assert too_many_categories.status_code == 422
    assert _error_code(too_many_categories) == "invalid_request"
    assert "categories" in too_many_categories.json()["error"]["message"]
    assert too_many_targets.status_code == 422
    assert _error_code(too_many_targets) == "invalid_request"
    assert "user_targets" in too_many_targets.json()["error"]["message"]


def test_unexpected_errors_are_structured_without_logging_raw_values(
    monkeypatch,
    caplog,
    tmp_path,
):
    raw_target = "RAW-NEVER-LOG-123-45-6789"

    def fail_without_echo(_request):
        raise RuntimeError(raw_target)

    monkeypatch.setattr(main_module.session_store, "create_pending", fail_without_echo)
    safe_client = TestClient(
        app,
        base_url="http://127.0.0.1:8000",
        headers={AUTH_HEADER: launch_token},
        raise_server_exceptions=False,
    )

    response = safe_client.post("/scans", json={"paths": [str(tmp_path)]})

    def fail_for_path(_scan_id):
        raise RuntimeError("generic failure")

    monkeypatch.setattr(main_module.session_store, "get", fail_for_path)
    path_response = safe_client.get(f"/scans/{raw_target}")

    assert response.status_code == 500
    assert path_response.status_code == 500
    assert _error_code(response) == "internal_error"
    assert raw_target not in response.text
    assert raw_target not in path_response.text
    assert raw_target not in caplog.text
    assert launch_token not in caplog.text


def test_detectors_lists_builtin_detectors():
    response = client.get("/detectors")
    assert response.status_code == 200
    ids = {detector["id"] for detector in response.json()}
    assert "us_ssn" in ids
    assert "aws_access_key" in ids


def test_create_scan_returns_privacy_safe_public_findings(tmp_path):
    raw_secret = "123-45-6789"
    (tmp_path / "secrets.py").write_text(f'ssn = "{raw_secret}"\n')

    response = client.post("/scans", json={"paths": [str(tmp_path)]})

    assert response.status_code == 201
    created = response.json()
    assert created["state"] in {"pending", "discovering", "scanning", "complete"}
    body = _wait_for_terminal(created["scan_id"])
    assert body["state"] == "complete"
    finding = next(item for item in body["findings"] if item["detector_id"] == "us_ssn")
    assert finding["tier"] == "A"
    assert finding["redacted_preview"] == "12*******89"
    assert {"matched_text", "start_offset", "end_offset", "evidence"}.isdisjoint(finding)
    assert raw_secret not in json.dumps(body)
    assert len(body["scan_id"]) >= 32
    assert body["created_at"]
    assert body["expires_at"]
    assert body["llm_used"] is False
    assert body["metadata"]["selected_roots"] == [str(tmp_path.resolve())]
    assert body["metadata"]["duration_ms"] >= 0
    assert body["metadata"]["data_scanned_bytes"] == (tmp_path / "secrets.py").stat().st_size
    assert body["metadata"]["detector_count"] > 0
    assert body["metadata"]["ai_model"] is None


def test_completed_scan_reveals_only_requested_server_owned_values(tmp_path):
    raw_secret = "123-45-6789"
    (tmp_path / "secrets.py").write_text(f'ssn = "{raw_secret}"\n')
    scan = _create_scan(tmp_path)
    finding = next(item for item in scan["findings"] if item["detector_id"] == "us_ssn")

    response = client.post(
        f"/scans/{scan['scan_id']}/reveal-findings",
        json={"finding_ids": [finding["id"], finding["id"]]},
    )
    forged = client.post(
        f"/scans/{scan['scan_id']}/reveal-findings",
        json={"finding_ids": [finding["id"], "not-from-this-scan"]},
    )

    assert response.status_code == 200
    assert response.json() == {"values": [{"finding_id": finding["id"], "value": raw_secret}]}
    assert response.headers["cache-control"] == "no-store"
    assert forged.status_code == 404
    assert _error_code(forged) == "finding_not_found"
    assert raw_secret not in forged.text


def test_browser_scan_accepts_bounded_scope_options_and_returns_structured_skips(
    tmp_path,
):
    included = tmp_path / "included.txt"
    excluded = tmp_path / "excluded.py"
    included.write_text("123-45-6789\n")
    excluded.write_text("987-65-4321\n")

    response = client.post(
        "/scans",
        json={
            "paths": [str(tmp_path)],
            "options": {
                "included_extensions": ["txt"],
                "max_workers": 1,
                "document_workers": 1,
                "chunk_size": 65_536,
            },
        },
    )

    assert response.status_code == 201
    body = _wait_for_terminal(response.json()["scan_id"])
    assert body["state"] == "complete"
    assert body["scanned_files"] == [str(included)]
    skipped = body["skipped_files"][0]
    assert skipped["path"] == str(excluded)
    assert skipped["code"] == "extension_not_included"
    assert skipped["stage"] == "discovery"


def test_browser_scan_applies_all_file_scope_and_size_controls(tmp_path):
    ordinary = tmp_path / "ordinary.txt"
    ignored_by_file = tmp_path / "kept-by-disabled-ignore.txt"
    excluded = tmp_path / "bundle.min.js"
    oversized_text = tmp_path / "oversized.txt"
    oversized_document = tmp_path / "oversized.pdf"
    ignored_directory = tmp_path / "vendor"
    ignored_directory.mkdir()
    (ignored_directory / "secret.txt").write_text("123-45-6789\n")
    ordinary.write_text("123-45-6789\n")
    ignored_by_file.write_text("987-65-4321\n")
    excluded.write_text("111-22-3333\n")
    oversized_text.write_text("x" * 2_000)
    oversized_document.write_bytes(b"%PDF" + (b"x" * 2_000))
    (tmp_path / ".redactlensignore").write_text("kept-by-disabled-ignore.txt\n")

    response = client.post(
        "/scans",
        json={
            "paths": [str(tmp_path)],
            "options": {
                "max_file_size": 1_000,
                "max_structured_file_size": 500,
                "ignored_directories": ["vendor"],
                "excluded_extensions": [".min.js"],
                "use_redactlensignore": False,
                "max_workers": 1,
                "document_workers": 1,
            },
        },
    )

    assert response.status_code == 201
    body = _wait_for_terminal(response.json()["scan_id"])
    assert body["state"] == "complete"
    assert body["scanned_files"] == sorted(
        [str(ignored_by_file), str(ordinary)], key=os.path.normcase
    )
    skips = {Path(item["path"]).name: item["code"] for item in body["skipped_files"]}
    assert skips == {
        "bundle.min.js": "excluded_extension",
        "oversized.pdf": "structured_file_too_large",
        "oversized.txt": "file_too_large",
        "vendor": "ignored_directory",
    }


def test_browser_scan_rejects_internally_inconsistent_worker_limits(tmp_path):
    response = client.post(
        "/scans",
        json={
            "paths": [str(tmp_path)],
            "options": {"max_workers": 1, "document_workers": 2},
        },
    )

    assert response.status_code == 422


def test_scan_does_not_log_raw_matches_targets_or_source_context(caplog, tmp_path):
    raw_target = "CUSTOM-NEVER-LOG-2468"
    source_context = f"private customer context around {raw_target}"
    (tmp_path / "private.txt").write_text(source_context)
    caplog.set_level(logging.DEBUG)

    body = _create_scan(
        tmp_path,
        user_targets=[{"kind": "literal", "value": raw_target, "category": "custom"}],
    )

    assert body["state"] == "complete"
    assert raw_target not in caplog.text
    assert source_context not in caplog.text


def test_create_scan_returns_before_background_work_completes(monkeypatch, tmp_path):
    target = tmp_path / "secrets.py"
    target.write_text('ssn = "123-45-6789"\n')
    started = threading.Event()
    release = threading.Event()
    real_scan = main_module.core_scan

    def blocked_scan(request, registry, **kwargs):
        started.set()
        release.wait(timeout=2)
        return real_scan(request, registry, **kwargs)

    monkeypatch.setattr(main_module, "core_scan", blocked_scan)

    try:
        response = client.post("/scans", json={"paths": [str(target)]})

        assert response.status_code == 201
        assert started.wait(timeout=1)
        created = response.json()
        assert created["state"] in {"pending", "discovering", "scanning"}
        assert created["progress"]["percent"] < 100
        release.set()
        assert _wait_for_terminal(created["scan_id"])["state"] == "complete"
    finally:
        release.set()


def test_scan_events_are_replayable_ordered_and_privacy_safe(tmp_path):
    raw_secret = "123-45-6789"
    target = tmp_path / "secrets.py"
    target.write_text(f'ssn = "{raw_secret}"\n')
    scan = _create_scan(target)

    response = client.get(f"/scans/{scan['scan_id']}/events")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    events = _sse_events(response)
    sequences = [event["sequence"] for event in events]
    assert sequences == sorted(sequences)
    assert len(sequences) == len(set(sequences))
    assert events[-1]["type"] == "scan_completed"
    assert scan["event_cursor"] == sequences[-1]
    finding_event = next(event for event in events if event["type"] == "finding_added")
    assert finding_event["finding"]["redacted_preview"] == "12*******89"
    assert {"matched_text", "start_offset", "end_offset", "evidence"}.isdisjoint(
        finding_event["finding"]
    )
    assert raw_secret not in response.text

    replay = client.get(
        f"/scans/{scan['scan_id']}/events",
        headers={"Last-Event-ID": str(sequences[-2])},
    )
    assert [event["sequence"] for event in _sse_events(replay)] == [sequences[-1]]


def test_scan_events_keep_exact_protocol_for_discovery_and_processing_skips(tmp_path):
    secret = tmp_path / "secret.py"
    binary = tmp_path / "binary.bin"
    excluded = tmp_path / "excluded.txt"
    secret.write_text('ssn = "123-45-6789"\n')
    binary.write_bytes(b"\x00\x01\x02")
    excluded.write_text('ssn = "987-65-4321"\n')
    scan = _create_scan(
        tmp_path,
        options={
            "included_extensions": [".py", ".bin"],
            "max_workers": 1,
        },
    )

    response = client.get(f"/scans/{scan['scan_id']}/events")

    assert response.status_code == 200
    events = _sse_events(response)
    sequences = [event["sequence"] for event in events]
    assert sequences == list(range(sequences[0], sequences[0] + len(sequences)))
    assert [event["type"] for event in events] == [
        "scan_started",
        "discovery_complete",
        "file_started",
        "file_skipped",
        "file_started",
        "file_skipped",
        "finding_added",
        "file_completed",
        "scan_finalizing",
        "scan_completed",
    ]
    completed = [event["progress"]["completed_files"] for event in events]
    skipped = [event["progress"]["skipped_files"] for event in events]
    percents = [event["progress"]["percent"] for event in events]
    assert completed == [0, 0, 0, 1, 1, 2, 2, 3, 3, 3]
    assert skipped == [0, 0, 0, 1, 1, 2, 2, 2, 2, 2]
    assert percents == sorted(percents)
    assert percents[-1] == 100
    for event in events[1:]:
        assert event["progress"]["total_files"] == 3
    skip_events = [event for event in events if event["type"] == "file_skipped"]
    assert {event["skipped_file"]["stage"] for event in skip_events} == {
        "discovery",
        "extraction",
    }
    assert len({event["skipped_file"]["path"] for event in skip_events}) == 2


def test_connected_event_stream_refreshes_idle_access_between_live_polls(
    monkeypatch,
    tmp_path,
    isolated_session_store,
):
    clock, store = isolated_session_store
    started_at = clock.value
    session = store.create_pending(ScanRequest(paths=[str(tmp_path)]))
    session.scan_state = "scanning"
    session.worker_thread = threading.current_thread()
    session.active_retention_deadline_clock = started_at + 300
    original_wait = session.wait_for_events
    original_touch = store.touch
    touch_times: list[float] = []
    wait_count = 0

    def record_touch(candidate):
        retained = original_touch(candidate)
        touch_times.append(candidate.last_accessed_clock)
        return retained

    def advance_between_polls(after: int, timeout: float):
        nonlocal wait_count
        wait_count += 1
        if wait_count == 1:
            clock.advance(30)
            return []
        if wait_count == 2:
            session.finish(
                ScanResult(
                    summary={
                        "status": "complete",
                        "incomplete": False,
                        "completed_files": 0,
                        "total_files": 0,
                    }
                ),
                state="complete",
            )
        return original_wait(after, timeout=0.0)

    monkeypatch.setattr(store, "touch", record_touch)
    monkeypatch.setattr(session, "wait_for_events", advance_between_polls)

    response = client.get(f"/scans/{session.scan_id}/events")

    assert response.status_code == 200
    assert touch_times == [started_at, started_at + 30]
    assert ": keepalive" in response.text
    assert [event["type"] for event in _sse_events(response)] == ["scan_completed"]


def test_category_projection_is_consistent_in_snapshot_and_sse(tmp_path):
    connection = "postgres://admin:CorrectHorseBattery9@prod-db.internal:5432/appdb"
    contact = "jane.doe@redactlensteam.io"
    target = tmp_path / "config.py"
    target.write_text(f'DATABASE_URL = "{connection}"\ncontact = "{contact}"\n')

    scan = _create_scan(target, categories=["personal_id"])

    assert scan["state"] == "complete"
    assert len(scan["findings"]) == 1
    finding = scan["findings"][0]
    assert finding["detector_id"] == "email"
    assert finding["supporting_detections"] == []
    assert scan["summary"]["raw_detector_hits"] == 1
    assert scan["summary"]["canonical_findings"] == 1
    assert scan["summary"]["consolidated_hits"] == 0
    assert scan["summary"]["suppressed_hits"] == 0
    assert scan["summary"]["raw_detector_hits_by_detector"] == {"email": 1}

    response = client.get(f"/scans/{scan['scan_id']}/events")
    finding_events = [
        event for event in _sse_events(response) if event["type"].startswith("finding_")
    ]
    assert [(event["type"], event["finding"]["id"]) for event in finding_events] == [
        ("finding_added", finding["id"])
    ]
    assert connection not in response.text
    assert contact not in response.text


def test_event_stream_closes_when_requested_replay_has_been_pruned(
    tmp_path,
    isolated_session_store,
):
    _clock, store = isolated_session_store
    session = store.create_pending(ScanRequest(paths=[str(tmp_path)]))
    session.max_events = 2
    session.apply_core_event(ScanEvent(type="scan_started", stage="discovery"))
    session.apply_core_event(ScanEvent(type="discovery_complete", stage="discovery", total_files=1))
    session.apply_core_event(
        ScanEvent(
            type="file_started",
            stage="extraction",
            file_path="example.py",
            total_files=1,
        )
    )

    response = client.get(f"/scans/{session.scan_id}/events?after=0")

    assert response.status_code == 200
    assert "retry: 1000" in response.text
    assert _sse_events(response) == []
    assert session.response().event_cursor == 3


def test_event_stream_drains_terminal_event_if_terminal_lands_after_wait(
    monkeypatch,
    tmp_path,
    isolated_session_store,
):
    _clock, store = isolated_session_store
    session = store.create_pending(ScanRequest(paths=[str(tmp_path)]))
    original_wait = session.wait_for_events
    raced = False

    def racing_wait(after: int, timeout: float):
        nonlocal raced
        if not raced:
            raced = True
            session.finish(
                ScanResult(
                    summary={
                        "status": "complete",
                        "incomplete": False,
                        "completed_files": 0,
                        "total_files": 0,
                    }
                ),
                state="complete",
            )
            return []
        return original_wait(after, timeout)

    monkeypatch.setattr(session, "wait_for_events", racing_wait)

    response = client.get(f"/scans/{session.scan_id}/events")
    events = _sse_events(response)

    assert [event["type"] for event in events] == ["scan_completed"]
    assert session.response().event_cursor == events[-1]["sequence"]


def test_active_job_is_not_evicted_when_max_sessions_rejects_a_new_scan(
    monkeypatch,
    tmp_path,
):
    target = tmp_path / "secrets.py"
    target.write_text('ssn = "123-45-6789"\n')
    store = ScanSessionStore(max_sessions=1)
    monkeypatch.setattr(main_module, "session_store", store)
    started = threading.Event()
    release = threading.Event()
    real_scan = main_module.core_scan

    def blocked_scan(request, registry, **kwargs):
        started.set()
        release.wait(timeout=2)
        return real_scan(request, registry, **kwargs)

    monkeypatch.setattr(main_module, "core_scan", blocked_scan)
    first_response = client.post("/scans", json={"paths": [str(target)]})
    assert first_response.status_code == 201
    first_id = first_response.json()["scan_id"]
    assert started.wait(timeout=1)

    try:
        rejected = client.post("/scans", json={"paths": [str(target)]})

        assert rejected.status_code == 503
        assert _error_code(rejected) == "session_capacity"
        first = store.get(first_id)
        assert first.active is True
        assert first.discarded is False
        assert first.worker_thread is not None and first.worker_thread.is_alive()
    finally:
        release.set()
        first = store.get(first_id)
        assert first.worker_thread is not None
        first.worker_thread.join(timeout=2)
        store.clear()


def test_delete_active_scan_requests_cooperative_cancellation(monkeypatch, tmp_path):
    target = tmp_path / "secrets.py"
    target.write_text('ssn = "123-45-6789"\n')
    started = threading.Event()
    cancellation_observed = threading.Event()

    def cancellable_scan(request, registry, **kwargs):
        execution = kwargs["execution"]
        started.set()
        deadline = time.monotonic() + 2
        while not execution.cancel_requested() and time.monotonic() < deadline:
            time.sleep(0.005)
        if not execution.cancel_requested():
            raise AssertionError("the API did not request cooperative cancellation")
        cancellation_observed.set()
        raise ScanCancelled(
            "Scan cancelled by request.",
            ScanResult(
                summary={
                    "status": "cancelled",
                    "incomplete": True,
                    "completed_files": 0,
                    "total_files": 1,
                }
            ),
        )

    monkeypatch.setattr(main_module, "core_scan", cancellable_scan)
    created = client.post("/scans", json={"paths": [str(target)]}).json()
    assert started.wait(timeout=1)

    deleted = client.delete(f"/scans/{created['scan_id']}")
    cancelled = _wait_for_terminal(created["scan_id"])

    assert deleted.status_code == 204
    assert cancellation_observed.is_set()
    assert cancelled["state"] == "cancelled"
    assert cancelled["summary"]["incomplete"] is True
    assert cancelled["error"]["code"] == "scan_cancelled"


def test_incomplete_scan_rejects_file_actions(monkeypatch, tmp_path):
    target = tmp_path / "secrets.py"
    target.write_text('ssn = "123-45-6789"\n')
    started = threading.Event()
    release = threading.Event()
    real_scan = main_module.core_scan

    def blocked_scan(request, registry, **kwargs):
        started.set()
        release.wait(timeout=2)
        return real_scan(request, registry, **kwargs)

    monkeypatch.setattr(main_module, "core_scan", blocked_scan)
    created = client.post("/scans", json={"paths": [str(target)]}).json()
    assert started.wait(timeout=1)

    try:
        responses = _incomplete_action_responses(created["scan_id"])
        assert len(responses) == 6
        for response in responses:
            assert response.status_code == 409
            assert _error_code(response) == "scan_incomplete"
    finally:
        release.set()
        _wait_for_terminal(created["scan_id"])


def test_scan_serializes_one_canonical_finding_with_supporting_evidence(tmp_path):
    (tmp_path / "config.py").write_text('AWS_ACCESS_KEY_ID = "AKIAV3XZJH2QK7RSTUV1"\n')

    body = _create_scan(tmp_path)

    assert len(body["findings"]) == 1
    finding = body["findings"][0]
    assert finding["detector_id"] == "aws_access_key"
    assert [item["detector_id"] for item in finding["supporting_detections"]] == [
        "high_entropy_secret"
    ]
    assert body["summary"]["raw_detector_hits"] == 2
    assert body["summary"]["canonical_findings"] == 1


def test_get_scan_refreshes_and_returns_the_public_result(tmp_path, isolated_session_store):
    clock, _store = isolated_session_store
    (tmp_path / "secrets.py").write_text('ssn = "123-45-6789"\n')
    created = _create_scan(tmp_path)
    first_expiry = created["expires_at"]

    clock.advance(10)
    response = client.get(f"/scans/{created['scan_id']}")

    assert response.status_code == 200
    assert response.json()["scan_id"] == created["scan_id"]
    assert response.json()["expires_at"] > first_expiry


def test_scan_respects_tier_threshold(tmp_path):
    (tmp_path / "secrets.py").write_text('ssn = "123-45-6789"\n')

    body = _create_scan(tmp_path, tier_threshold=0.99)

    ssn_finding = next(item for item in body["findings"] if item["detector_id"] == "us_ssn")
    assert ssn_finding["tier"] == "B"


def test_remediation_plan_generates_verified_redacted_copy(tmp_path):
    original = tmp_path / "secrets.py"
    original.write_text('ssn = "123-45-6789"\n')
    scan = _create_scan(tmp_path)
    finding_id = scan["findings"][0]["id"]

    plan_response = _update_plan(scan["scan_id"], [finding_id])
    response = _generate(scan["scan_id"])

    assert plan_response.status_code == 200
    assert plan_response.json()["selected_finding_count"] == 1
    assert response.status_code == 200
    output = response.json()["outputs"][0]
    redacted_path = Path(output["output_path"])
    assert redacted_path.name == "secrets-auto-redacted-copy.py"
    assert "123-45-6789" in original.read_text()
    assert "123-45-6789" not in redacted_path.read_text()
    assert output["applied_finding_ids"] == [finding_id]
    assert output["verification_status"] == "verified"
    assert len(output["source_fingerprint"]["sha256"]) == 64
    assert response.json()["plan"]["files"][0]["output_state"] == "current"


def test_remediation_plan_can_atomically_replace_the_verified_original(tmp_path):
    original = tmp_path / "secrets.py"
    original.write_text('ssn = "123-45-6789"\n')
    scan = _create_scan(original)
    finding_id = scan["findings"][0]["id"]

    _update_plan(scan["scan_id"], [finding_id])
    response = _generate(scan["scan_id"], output_mode="replace_original")

    assert response.status_code == 200
    output = response.json()["outputs"][0]
    assert Path(output["output_path"]) == original
    assert "123-45-6789" not in original.read_text()
    assert not (tmp_path / "secrets-auto-redacted-copy.py").exists()
    assert output["verification_status"] == "verified"
    assert any("original file was replaced" in warning for warning in output["warnings"])
    assert response.json()["plan"]["files"][0]["output_state"] == "current"
    assert response.json()["plan"]["can_generate"] is False


def test_remediation_api_preserves_included_ignored_and_pending_states(tmp_path):
    password = "FirstSecret123!"
    ssn = "123-45-6789"
    email = "jane.doe@redactlensteam.io"
    original = tmp_path / "mixed-actions.txt"
    original.write_text(
        f'password = "{password}"\nssn = "{ssn}"\nemail = "{email}"\n',
        encoding="utf-8",
    )
    scan = _create_scan(original)
    findings = {item["detector_id"]: item for item in scan["findings"]}
    assert {"password_assignment", "us_ssn", "email"} <= findings.keys()

    included_id = findings["password_assignment"]["id"]
    ignored_id = findings["us_ssn"]["id"]
    pending_id = findings["email"]["id"]
    updated = _update_plan(scan["scan_id"], [included_id], [ignored_id])

    assert updated.status_code == 200
    states = {item["finding_id"]: item["state"] for item in updated.json()["findings"]}
    assert states[included_id] == "included"
    assert states[ignored_id] == "ignored"
    assert states[pending_id] == "pending"

    generated = _generate(scan["scan_id"])

    assert generated.status_code == 200
    body = generated.json()
    persisted_states = {item["finding_id"]: item["state"] for item in body["plan"]["findings"]}
    assert persisted_states == states
    assert body["outputs"][0]["applied_finding_ids"] == [included_id]
    redacted = Path(body["outputs"][0]["output_path"]).read_text(encoding="utf-8")
    assert password not in redacted
    assert ssn in redacted
    assert email in redacted


def test_remediation_revision_binds_updates_and_generation_to_reviewed_plan(tmp_path):
    original = tmp_path / "secrets.py"
    original.write_text('ssn = "123-45-6789"\n')
    scan = _create_scan(original)
    finding_id = scan["findings"][0]["id"]
    initial = client.get(f"/scans/{scan['scan_id']}/remediation").json()

    updated = _update_plan(
        scan["scan_id"],
        [finding_id],
        plan_revision=initial["plan_revision"],
    )
    stale_update = _update_plan(
        scan["scan_id"],
        [],
        plan_revision=initial["plan_revision"],
    )
    stale_generation = _generate(
        scan["scan_id"],
        plan_revision=initial["plan_revision"],
    )

    assert updated.status_code == 200
    assert updated.json()["plan_revision"] == initial["plan_revision"] + 1
    assert stale_update.status_code == 409
    assert _error_code(stale_update) == "invalid_remediation_plan"
    assert stale_generation.status_code == 409
    assert _error_code(stale_generation) == "invalid_remediation_plan"
    assert not (tmp_path / "secrets-auto-redacted-copy.py").exists()


def test_forged_finding_id_is_rejected_from_plan_without_writing(tmp_path):
    original = tmp_path / "secrets.py"
    original.write_text('ssn = "123-45-6789"\n')
    scan = _create_scan(tmp_path)

    response = _update_plan(scan["scan_id"], ["forged-finding-id"])

    assert response.status_code == 404
    assert _error_code(response) == "finding_not_found"
    assert not (tmp_path / "secrets-auto-redacted-copy.py").exists()


def test_remediation_plan_rejects_client_paths_offsets_raw_values_and_in_place(
    tmp_path,
):
    original = tmp_path / "secrets.py"
    original.write_text('ssn = "123-45-6789"\n')
    scan = _create_scan(original)

    response = client.put(
        f"/scans/{scan['scan_id']}/remediation",
        json={
            "plan_revision": _plan_revision(scan["scan_id"]),
            "included_finding_ids": [scan["findings"][0]["id"]],
            "ignored_finding_ids": [],
            "file_path": str(original),
            "start_offset": 0,
            "matched_text": "forged",
            "in_place": True,
        },
    )

    assert response.status_code == 422
    assert not (tmp_path / "secrets-auto-redacted-copy.py").exists()
    assert "123-45-6789" in original.read_text()


def test_changed_file_is_rejected_before_generation(tmp_path):
    original = tmp_path / "secrets.py"
    original.write_text('ssn = "123-45-6789"\n')
    scan = _create_scan(tmp_path)
    original.write_text('ssn = "987-65-4321"\n')

    _update_plan(scan["scan_id"], [scan["findings"][0]["id"]])
    response = _generate(scan["scan_id"])

    assert response.status_code == 409
    assert _error_code(response) == "file_changed"
    assert not (tmp_path / "secrets-auto-redacted-copy.py").exists()


def test_file_changed_during_scan_fails_the_background_job(
    monkeypatch,
    tmp_path,
    isolated_session_store,
):
    target = tmp_path / "secrets.py"
    target.write_text('ssn = "123-45-6789"\n')
    real_scan = main_module.core_scan

    def scan_then_change(request, registry, **kwargs):
        result = real_scan(request, registry, **kwargs)
        target.write_text('ssn = "987-65-4321"\n')
        return result

    monkeypatch.setattr(main_module, "core_scan", scan_then_change)

    response = client.post("/scans", json={"paths": [str(target)]})

    assert response.status_code == 201
    body = _wait_for_terminal(response.json()["scan_id"])
    assert body["state"] == "failed"
    assert body["error"]["code"] == "file_changed"
    assert body["summary"]["status"] == "failed"
    assert body["summary"]["incomplete"] is True
    assert body["findings"]
    assert "123-45-6789" not in json.dumps(body)

    _clock, store = isolated_session_store
    session = store.get(body["scan_id"])
    assert session.internal_findings == {}
    assert session.file_fingerprints == {}
    assert session.remediation_states == {}
    assert session.request is None


def test_missing_file_returns_structured_file_unavailable_error(tmp_path):
    original = tmp_path / "secrets.py"
    original.write_text('ssn = "123-45-6789"\n')
    scan = _create_scan(tmp_path)
    original.unlink()

    _update_plan(scan["scan_id"], [scan["findings"][0]["id"]])
    response = _generate(scan["scan_id"])

    assert response.status_code == 410
    assert _error_code(response) == "file_unavailable"


def test_existing_output_returns_structured_conflict_without_overwrite(tmp_path):
    original = tmp_path / "secrets.py"
    original.write_text('ssn = "123-45-6789"\n')
    existing_output = tmp_path / "secrets-auto-redacted-copy.py"
    existing_output.write_text("keep me")
    scan = _create_scan(original)

    _update_plan(scan["scan_id"], [scan["findings"][0]["id"]])
    response = _generate(scan["scan_id"])

    assert response.status_code == 409
    assert _error_code(response) == "output_conflict"
    assert existing_output.read_text() == "keep me"


@pytest.mark.parametrize("failure_point", ["staging", "commit"])
def test_atomic_generation_failures_leave_session_and_files_recoverable(
    monkeypatch,
    tmp_path,
    isolated_session_store,
    failure_point,
):
    secrets = ("123-45-6789", "987-65-4321")
    sources = [tmp_path / "first.py", tmp_path / "second.py"]
    for source, secret in zip(sources, secrets, strict=True):
        source.write_text(f'ssn = "{secret}"\n')
    scan = _create_scan(tmp_path)
    finding_ids = [finding["id"] for finding in scan["findings"]]
    updated = _update_plan(scan["scan_id"], finding_ids)
    revision = updated.json()["plan_revision"]

    if failure_point == "staging":
        real_stage = atomic._stage_bytes
        stage_calls = 0

        def fail_second_stage(target, contents, *, label="tmp"):
            nonlocal stage_calls
            stage_calls += 1
            if stage_calls == 2:
                raise OSError("simulated staging failure")
            return real_stage(target, contents, label=label)

        monkeypatch.setattr(atomic, "_stage_bytes", fail_second_stage)
    else:
        real_link = atomic.os.link

        def fail_second_commit(source, target):
            if Path(target).name == "second-auto-redacted-copy.py":
                raise OSError("simulated commit failure")
            return real_link(source, target)

        monkeypatch.setattr(atomic.os, "link", fail_second_commit)

    response = _generate(scan["scan_id"], plan_revision=revision)

    assert response.status_code == 410
    assert response.json() == {
        "error": {
            "code": "file_unavailable",
            "message": "Could not create the redacted copies. Check the destination permissions.",
        }
    }
    assert all(
        not source.with_name(f"{source.stem}-auto-redacted-copy{source.suffix}").exists()
        for source in sources
    )
    assert list(tmp_path.glob(".*.tmp")) == []
    assert not any(secret in response.text for secret in secrets)

    _clock, store = isolated_session_store
    session = store.get(scan["scan_id"])
    assert session.scan_state == "complete"
    assert session.remediation_revision == revision
    assert session.generated_outputs == {}
    assert set(session.remediation_states.values()) == {"included"}
    plan = client.get(f"/scans/{scan['scan_id']}/remediation")
    assert plan.status_code == 200
    assert plan.json()["can_generate"] is True
    assert {file["output_state"] for file in plan.json()["files"]} == {"not_created"}


def test_externally_modified_session_output_is_not_overwritten_on_regeneration(
    tmp_path,
):
    original = tmp_path / "secrets.txt"
    original.write_bytes(b"password = FirstSecret123!\nssn = 123-45-6789\n")
    scan = _create_scan(original)
    finding_ids = [finding["id"] for finding in scan["findings"]]
    _update_plan(scan["scan_id"], [finding_ids[0]])
    output_path = Path(_generate(scan["scan_id"]).json()["outputs"][0]["output_path"])
    output_path.write_text("externally changed")
    _update_plan(scan["scan_id"], finding_ids)

    response = _generate(scan["scan_id"])

    assert response.status_code == 409
    assert _error_code(response) == "output_conflict"
    assert output_path.read_text() == "externally changed"


def test_read_only_document_finding_is_excluded_and_rejected_cleanly(tmp_path):
    document = tmp_path / "report.pdf"
    document.write_bytes(_pdf_document("ssn 123-45-6789"))
    scan = _create_scan(document)
    finding = scan["findings"][0]
    assert finding["can_anonymize"] is False

    initial_plan = client.get(f"/scans/{scan['scan_id']}/remediation")
    response = _update_plan(scan["scan_id"], [finding["id"]])

    assert initial_plan.json()["findings"][0]["state"] == "read_only"
    assert initial_plan.json()["read_only_finding_count"] == 1
    assert response.status_code == 400
    assert _error_code(response) == "finding_not_anonymizable"


def test_scan_reads_word_documents(tmp_path):
    document = tmp_path / "notes.docx"
    document.write_bytes(_word_document("ssn = 123-45-6789"))

    body = _create_scan(document)

    ssn = next(item for item in body["findings"] if item["detector_id"] == "us_ssn")
    assert ssn["location"] == "paragraph 1"
    assert ssn["can_anonymize"] is True


def test_generation_reopens_and_verifies_a_redacted_word_document(tmp_path):
    original = tmp_path / "notes.docx"
    original.write_bytes(_word_document("ssn = 123-45-6789"))
    scan = _create_scan(original)

    _update_plan(scan["scan_id"], [scan["findings"][0]["id"]])
    response = _generate(scan["scan_id"])

    assert response.status_code == 200
    output = response.json()["outputs"][0]
    redacted = Path(output["output_path"])
    assert redacted.name == "notes-auto-redacted-copy.docx"
    assert output["verification_status"] == "verified"
    with zipfile.ZipFile(redacted) as archive:
        content = archive.read("word/document.xml").decode()
    assert "123-45-6789" not in content
    assert "*******6789" in content
    assert "123-45-6789" in original.read_bytes().decode(errors="ignore")


def test_current_structured_output_keeps_its_recorded_path_if_source_disappears(
    tmp_path,
):
    original = tmp_path / "notes.docx"
    original.write_bytes(_word_document("ssn = 123-45-6789"))
    scan = _create_scan(original)
    _update_plan(scan["scan_id"], [scan["findings"][0]["id"]])
    generated = _generate(scan["scan_id"]).json()
    generated_path = generated["outputs"][0]["output_path"]
    original.unlink()

    plan = client.get(f"/scans/{scan['scan_id']}/remediation")

    assert plan.status_code == 200
    assert plan.json()["files"][0]["output_state"] == "current"
    assert plan.json()["files"][0]["output_path"] == generated_path


def test_full_scan_remediation_rescan_workflow_is_ordered_and_privacy_safe(monkeypatch, tmp_path):
    """Exercise the portfolio-critical workflow across API and core boundaries."""
    first_secret = "123-45-6789"
    second_secret = "987-65-4321"
    original = tmp_path / "customer-records.txt"
    original.write_text(
        f"primary ssn = {first_secret}\nbackup ssn = {second_secret}\n",
        encoding="utf-8",
    )
    opened: list[str] = []
    monkeypatch.setattr("redactlens_api.main.open_file", opened.append)

    scan = _create_scan(original)
    events_response = client.get(f"/scans/{scan['scan_id']}/events")
    events = _sse_events(events_response)
    sequences = [event["sequence"] for event in events]
    percents = [event["progress"]["percent"] for event in events]

    assert events_response.status_code == 200
    assert sequences == sorted(sequences)
    assert percents == sorted(percents)
    assert events[0]["type"] == "scan_started"
    assert any(event["type"] == "finding_added" for event in events[:-1])
    assert events[-1]["type"] == "scan_completed"

    selected_ids = [
        finding["id"]
        for finding in scan["findings"]
        if finding["tier"] == "A" and finding["can_anonymize"]
    ]
    assert len(selected_ids) == 2
    plan = _update_plan(scan["scan_id"], selected_ids)
    generated = _generate(scan["scan_id"])

    assert plan.status_code == 200
    assert plan.json()["selected_finding_count"] == 2
    assert generated.status_code == 200
    output = generated.json()["outputs"][0]
    output_path = Path(output["output_path"])
    assert output["verification_status"] == "verified"
    assert output["applied_finding_ids"] == selected_ids
    assert first_secret not in output_path.read_text()
    assert second_secret not in output_path.read_text()

    opened_response = client.post(
        f"/scans/{scan['scan_id']}/open-output",
        json={"finding_id": selected_ids[0]},
    )
    rescanned = _create_scan(output_path)

    assert opened_response.status_code == 200
    assert opened == [str(output_path)]
    assert not [finding for finding in rescanned["findings"] if finding["tier"] == "A"]
    serialized_public_workflow = "\n".join(
        [
            json.dumps(scan),
            events_response.text,
            plan.text,
            generated.text,
            opened_response.text,
            json.dumps(rescanned),
        ]
    )
    assert first_secret not in serialized_public_workflow
    assert second_secret not in serialized_public_workflow


def test_pick_path_returns_the_chosen_path(monkeypatch):
    monkeypatch.setattr("redactlens_api.main.pick_path", lambda kind: "C:\\Users\\me\\project")

    response = client.post("/pick-path?kind=folder")

    assert response.status_code == 200
    assert response.json() == {"path": "C:\\Users\\me\\project"}


def test_pick_path_reports_501_when_no_picker_is_available(monkeypatch):
    from redactlens_api.pick import PickerUnavailable

    def boom(kind):
        raise PickerUnavailable("no display")

    monkeypatch.setattr("redactlens_api.main.pick_path", boom)

    response = client.post("/pick-path?kind=folder")

    assert response.status_code == 501
    assert _error_code(response) == "picker_unavailable"


def test_open_file_uses_the_server_side_path_for_a_session_finding(monkeypatch, tmp_path):
    opened = []
    monkeypatch.setattr("redactlens_api.main.open_file", opened.append)
    target = tmp_path / "secrets.py"
    target.write_text('ssn = "123-45-6789"\n')
    scan = _create_scan(target)
    finding_id = scan["findings"][0]["id"]

    response = client.post(
        f"/scans/{scan['scan_id']}/open-file",
        json={"finding_id": finding_id},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert opened == [str(target)]


def test_open_errors_do_not_disclose_a_match_repeated_in_the_filename(monkeypatch, tmp_path):
    raw_secret = "123-45-6789"
    target = tmp_path / f"employee-{raw_secret}.py"
    target.write_text(f'ssn = "{raw_secret}"\n')
    scan = _create_scan(target)
    finding_id = scan["findings"][0]["id"]

    def refuse_open(_path):
        raise OSError("simulated open failure")

    monkeypatch.setattr("redactlens_api.main.open_file", refuse_open)
    source_response = client.post(
        f"/scans/{scan['scan_id']}/open-file",
        json={"finding_id": finding_id},
    )

    assert source_response.status_code == 410
    assert _error_code(source_response) == "file_unavailable"
    assert raw_secret not in source_response.text

    _update_plan(scan["scan_id"], [finding_id])
    generated = _generate(scan["scan_id"])
    assert generated.status_code == 200
    output_response = client.post(
        f"/scans/{scan['scan_id']}/open-output",
        json={"finding_id": finding_id},
    )

    assert output_response.status_code == 410
    assert _error_code(output_response) == "file_unavailable"
    assert raw_secret not in output_response.text


def test_generation_conflict_error_does_not_disclose_match_from_filename(tmp_path):
    raw_secret = "123-45-6789"
    target = tmp_path / f"employee-{raw_secret}.py"
    target.write_text(f'ssn = "{raw_secret}"\n')
    existing_output = target.with_name(f"{target.stem}-auto-redacted-copy{target.suffix}")
    existing_output.write_text("existing output\n")
    scan = _create_scan(target)
    finding_id = scan["findings"][0]["id"]
    _update_plan(scan["scan_id"], [finding_id])

    response = _generate(scan["scan_id"])

    assert response.status_code == 409
    assert _error_code(response) == "output_conflict"
    assert raw_secret not in response.text
    assert existing_output.read_text() == "existing output\n"


def test_open_file_rejects_a_source_changed_after_the_scan(monkeypatch, tmp_path):
    opened = []
    monkeypatch.setattr("redactlens_api.main.open_file", opened.append)
    target = tmp_path / "secrets.py"
    target.write_text('ssn = "123-45-6789"\n')
    scan = _create_scan(target)
    finding_id = scan["findings"][0]["id"]
    target.write_text('ssn = "987-65-4321"\n')

    response = client.post(
        f"/scans/{scan['scan_id']}/open-file",
        json={"finding_id": finding_id},
    )

    assert response.status_code == 409
    assert _error_code(response) == "file_changed"
    assert "before showing it in its folder" in response.json()["error"]["message"]
    assert opened == []


def test_open_file_rejects_forged_id_and_does_not_accept_a_path(monkeypatch, tmp_path):
    opened = []
    monkeypatch.setattr("redactlens_api.main.open_file", opened.append)
    target = tmp_path / "secrets.py"
    target.write_text('ssn = "123-45-6789"\n')
    scan = _create_scan(target)

    forged_id = client.post(
        f"/scans/{scan['scan_id']}/open-file",
        json={"finding_id": "forged"},
    )
    forged_path = client.post(
        f"/scans/{scan['scan_id']}/open-file",
        json={"path": str(target)},
    )

    assert forged_id.status_code == 404
    assert _error_code(forged_id) == "finding_not_found"
    assert forged_path.status_code == 422
    assert opened == []


def test_open_redacted_copy_uses_verified_session_output(monkeypatch, tmp_path):
    opened = []
    monkeypatch.setattr("redactlens_api.main.open_file", opened.append)
    target = tmp_path / "secrets.py"
    target.write_text('ssn = "123-45-6789"\n')
    scan = _create_scan(target)
    finding_id = scan["findings"][0]["id"]
    _update_plan(scan["scan_id"], [finding_id])
    generated = _generate(scan["scan_id"]).json()["outputs"][0]

    response = client.post(
        f"/scans/{scan['scan_id']}/open-output",
        json={"finding_id": finding_id},
    )

    assert response.status_code == 200
    assert opened == [generated["output_path"]]


def test_open_redacted_copy_rejects_output_changed_after_generation(
    monkeypatch,
    tmp_path,
):
    opened = []
    monkeypatch.setattr("redactlens_api.main.open_file", opened.append)
    target = tmp_path / "secrets.py"
    target.write_text('ssn = "123-45-6789"\n')
    scan = _create_scan(target)
    finding_id = scan["findings"][0]["id"]
    _update_plan(scan["scan_id"], [finding_id])
    generated = _generate(scan["scan_id"]).json()["outputs"][0]
    Path(generated["output_path"]).write_text("externally changed")

    response = client.post(
        f"/scans/{scan['scan_id']}/open-output",
        json={"finding_id": finding_id},
    )

    assert response.status_code == 409
    assert _error_code(response) == "output_conflict"
    assert opened == []


def test_selection_change_blocks_open_until_output_is_regenerated(monkeypatch, tmp_path):
    opened = []
    monkeypatch.setattr("redactlens_api.main.open_file", opened.append)
    target = tmp_path / "secrets.txt"
    target.write_text("password = FirstSecret123!\nssn = 123-45-6789\n")
    scan = _create_scan(target)
    first, second = [finding["id"] for finding in scan["findings"][:2]]
    _update_plan(scan["scan_id"], [first])
    _generate(scan["scan_id"])
    changed = _update_plan(scan["scan_id"], [first, second])

    response = client.post(
        f"/scans/{scan['scan_id']}/open-output",
        json={"finding_id": first},
    )

    assert changed.json()["files"][0]["output_state"] == "regeneration_required"
    assert response.status_code == 409
    assert _error_code(response) == "invalid_remediation_plan"
    assert opened == []


def test_expired_scan_returns_actionable_structured_error(tmp_path, isolated_session_store):
    clock, _store = isolated_session_store
    target = tmp_path / "secrets.py"
    target.write_text('ssn = "123-45-6789"\n')
    scan = _create_scan(target)
    clock.advance(61)

    response = client.get(f"/scans/{scan['scan_id']}")

    assert response.status_code == 410
    assert response.json() == {
        "error": {
            "code": "scan_expired",
            "message": "This scan has expired. Run it again before taking further action.",
        }
    }


def test_delete_scan_explicitly_expires_the_session(tmp_path):
    target = tmp_path / "secrets.py"
    target.write_text('ssn = "123-45-6789"\n')
    scan = _create_scan(target)

    deleted = client.delete(f"/scans/{scan['scan_id']}")
    fetched = client.get(f"/scans/{scan['scan_id']}")

    assert deleted.status_code == 204
    assert fetched.status_code == 410
    assert _error_code(fetched) == "scan_expired"


def test_unsafe_legacy_write_endpoints_are_not_available(tmp_path):
    payload = {"paths": [str(tmp_path)]}

    assert client.post("/scan", json=payload).status_code in {404, 405}
    assert client.post("/anonymize", json={"findings": []}).status_code in {404, 405}
    assert client.post("/scans/not-a-session/anonymize", json={"finding_ids": []}).status_code in {
        404,
        405,
    }
    assert client.post("/open-file", json={"path": str(tmp_path)}).status_code in {
        404,
        405,
    }


def test_openapi_docs_render():
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 200
