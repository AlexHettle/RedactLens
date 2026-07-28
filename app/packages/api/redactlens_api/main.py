"""Thin, local-only FastAPI backend over redactlens-core.

No detection, scoring, or anonymization logic lives here -- every endpoint
just deserializes a request, calls into redactlens-core, and serializes the
result. Bind to 127.0.0.1 only (see __main__.py); CORS is restricted to the
Vite dev server's localhost origins, never a wildcard.

If the frontend has been built (packages/frontend/dist exists), this app also serves
it at "/" -- one process is the whole app, which is what the one-click
launcher (launch.py) relies on.
"""

import logging
import os
import sys
import tempfile
import threading
import time
import traceback
from pathlib import Path
from typing import Any, Literal, get_args

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from redactlens_core.llm.adapter import DEFAULT_MODEL, OllamaAdapter
from redactlens_core.registry import load_default_registry
from redactlens_core.scanner import scan as core_scan
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import Scope

from .contracts import (
    BrowserScanRequest,
    GenerateRemediationRequest,
    LaunchSessionResponse,
    OpenFileResponse,
    OpenRedactedCopyRequest,
    PublicScanResult,
    RemediationGenerationResponse,
    RemediationPlan,
    RevealedFindingValue,
    RevealFindingsRequest,
    RevealFindingsResponse,
    SessionOpenFileRequest,
    UpdateRemediationRequest,
)
from .open_file import open_file
from .pick import PickerUnavailable, pick_path
from .security import (
    AUTH_HEADER,
    DEVELOPMENT_ORIGINS,
    LaunchSecurity,
    SecurityBoundaryMiddleware,
    api_error,
)
from .sessions import (
    EventReplayGap,
    ScanSessionStore,
    SessionProblem,
    generate_remediation_outputs,
    remediation_plan,
    session_file_for_finding,
    session_redacted_output_for_finding,
    update_remediation_plan,
)

app = FastAPI(
    title="RedactLens API",
    description="Local-first sensitive-data scanner backend. Localhost only.",
    version="0.1.0",
)

logger = logging.getLogger("redactlens_api")
launch_security = LaunchSecurity.from_environment()

session_store = ScanSessionStore.from_environment()
session_store.start_cleanup_worker()


@app.exception_handler(SessionProblem)
def session_problem_handler(_request: Request, error: SessionProblem) -> JSONResponse:
    return api_error(error.status_code, error.code, error.message)


@app.exception_handler(RequestValidationError)
def validation_problem_handler(request: Request, error: RequestValidationError) -> JSONResponse:
    declared_fields: set[str] = set()
    seen_models: set[type[BaseModel]] = set()

    def collect_model_fields(annotation: Any) -> None:
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            if annotation in seen_models:
                return
            seen_models.add(annotation)
            for name, field in annotation.model_fields.items():
                declared_fields.add(name)
                if isinstance(field.alias, str):
                    declared_fields.add(field.alias)
                collect_model_fields(field.annotation)
            return
        for nested in get_args(annotation):
            collect_model_fields(nested)

    route = request.scope.get("route")
    dependant = getattr(route, "dependant", None)
    if dependant is not None:
        for parameter_kind in ("path_params", "query_params", "body_params"):
            for parameter in getattr(dependant, parameter_kind, ()):
                declared_fields.add(parameter.name)
                if isinstance(parameter.alias, str):
                    declared_fields.add(parameter.alias)
                collect_model_fields(parameter.field_info.annotation)

    fields = sorted(
        {
            ".".join(
                part for part in item["loc"] if isinstance(part, str) and part in declared_fields
            )
            for item in error.errors()
            if item.get("type") != "extra_forbidden"
        }
    )
    named_fields = [field for field in fields if field]
    field_message = f" Check: {', '.join(named_fields)}." if named_fields else ""
    return api_error(422, "invalid_request", f"The request is invalid.{field_message}")


@app.exception_handler(StarletteHTTPException)
def http_problem_handler(_request: Request, error: StarletteHTTPException) -> JSONResponse:
    code = "not_found" if error.status_code == 404 else "method_not_allowed"
    message = (
        "That RedactLens endpoint does not exist."
        if error.status_code == 404
        else "That HTTP method is not allowed for this RedactLens endpoint."
    )
    return api_error(error.status_code, code, message)


@app.exception_handler(Exception)
def unexpected_problem_handler(request: Request, error: Exception) -> JSONResponse:
    # format_tb deliberately excludes the exception message and local values,
    # either of which could contain a raw target or document fragment.
    stack = "".join(traceback.format_tb(error.__traceback__))
    route = getattr(request.scope.get("route"), "path", "<unresolved route>")
    logger.error("Unhandled API failure on %s %s\n%s", request.method, route, stack)
    return api_error(500, "internal_error", "RedactLens could not complete that request.")


class DetectorInfo(BaseModel):
    id: str
    category: str
    description: str
    risk_lesson: str


class OllamaModelResponse(BaseModel):
    name: str
    size_bytes: int | None


class HealthResponse(BaseModel):
    status: str
    ollama_available: bool
    ollama_status: Literal["unavailable", "model_missing", "ready"]
    ollama_model: str
    ollama_models: list[OllamaModelResponse]


class PickPathResponse(BaseModel):
    path: str  # empty string when the user cancels the dialog


class AppearanceThemeRequest(BaseModel):
    theme: Literal["light", "dark"]


def _save_appearance_theme(theme: Literal["light", "dark"]) -> None:
    raw_path = os.environ.get("REDACTLENS_APPEARANCE_THEME_FILE")
    if not raw_path:
        return
    destination = Path(raw_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="ascii",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write(theme)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        os.replace(temporary_path, destination)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


@app.get("/launch-session")
def launch_session() -> LaunchSessionResponse:
    """Return the in-memory capability used by this allowed RedactLens frontend."""

    return LaunchSessionResponse(token=launch_security.token)


@app.put("/appearance/theme", status_code=204)
def save_appearance_theme(request: AppearanceThemeRequest) -> Response:
    """Remember the UI theme where the next native splash can read it."""

    _save_appearance_theme(request.theme)
    return Response(status_code=204)


@app.get("/health")
def health() -> HealthResponse:
    # Inventory checks should stay responsive while Ollama is still starting
    # with Windows. Full model calls keep their longer scan timeout.
    adapter = OllamaAdapter(timeout=2.0)
    local_models = adapter.local_models()
    if local_models is None:
        ollama_status: Literal["unavailable", "model_missing", "ready"] = "unavailable"
        local_models = []
    else:
        ollama_status = (
            "ready" if adapter.matching_model_info(local_models) is not None else "model_missing"
        )
    return HealthResponse(
        status="ok",
        ollama_available=ollama_status == "ready",
        ollama_status=ollama_status,
        ollama_model=adapter.model,
        ollama_models=[
            OllamaModelResponse(name=model.name, size_bytes=model.size) for model in local_models
        ],
    )


@app.post("/pick-path")
def pick_path_endpoint(kind: Literal["folder", "file"] = "folder") -> PickPathResponse:
    """Open a native folder/file picker on this machine and return the choice.

    ``kind`` is ``"folder"`` (default) or ``"file"``. Runs entirely locally --
    nothing about the selection leaves the device.
    """
    try:
        return PickPathResponse(path=pick_path(kind))
    except PickerUnavailable as error:
        raise SessionProblem(
            "picker_unavailable",
            "The native picker is unavailable. Type the path manually instead.",
            501,
        ) from error


@app.get("/detectors")
def detectors() -> list[DetectorInfo]:
    registry = load_default_registry()
    return [
        DetectorInfo(
            id=d.id,
            category=d.category,
            description=d.description,
            risk_lesson=d.risk_lesson,
        )
        for d in registry.get_all()
    ]


@app.post("/scans", status_code=201)
def create_scan(request: BrowserScanRequest) -> PublicScanResult:
    scan_request = request.to_internal()
    if scan_request.use_llm:
        requested_model = scan_request.ollama_model or DEFAULT_MODEL
        adapter = OllamaAdapter(model=requested_model)
        local_models = adapter.local_models()
        if local_models is None:
            raise SessionProblem(
                "ollama_unavailable",
                "Local AI could not start because Ollama is not running. "
                "Start Ollama, then choose Check again before scanning.",
                409,
            )
        selected_model = adapter.matching_model_info(local_models)
        if selected_model is None:
            raise SessionProblem(
                "ollama_model_unavailable",
                f"Local AI could not start because {requested_model} is not installed "
                "as a local model. Install it or choose an installed model under "
                "Advanced scan options, then try again.",
                409,
            )
        scan_request = scan_request.model_copy(update={"ollama_model": selected_model.name})
    session = session_store.create_pending(scan_request)
    session_store.start_job(session, scanner=core_scan)
    return session.response()


@app.get("/scans/{scan_id}")
def get_scan(scan_id: str) -> PublicScanResult:
    return session_store.get(scan_id).response()


@app.get("/scans/{scan_id}/events")
def get_scan_events(scan_id: str, request: Request, after: int = 0) -> StreamingResponse:
    session = session_store.get(scan_id)
    header_sequence = request.headers.get("last-event-id")
    if header_sequence:
        try:
            after = max(after, int(header_sequence))
        except ValueError:
            pass

    def stream():
        sequence = after
        yield "retry: 1000\n\n"
        while True:
            if not session_store.touch(session):
                break
            try:
                events = session.wait_for_events(sequence, timeout=10.0)
            except EventReplayGap:
                # The bounded replay log no longer contains a contiguous
                # continuation. Closing EventSource forces the client to
                # recover from the authoritative scan snapshot instead of
                # silently constructing an incomplete result.
                break
            for event in events:
                sequence = event.sequence
                yield f"id: {event.sequence}\ndata: {event.model_dump_json()}\n\n"
            if session.terminal:
                # A terminal transition can land just after a timed wait
                # returned no events. Drain once more before closing so the
                # final event is not lost to that race.
                try:
                    trailing = session.wait_for_events(sequence, timeout=0.0)
                except EventReplayGap:
                    break
                if trailing:
                    for event in trailing:
                        sequence = event.sequence
                        yield f"id: {event.sequence}\ndata: {event.model_dump_json()}\n\n"
                    continue
                break
            if not events:
                yield ": keepalive\n\n"

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/scans/{scan_id}/remediation")
def get_remediation_plan(scan_id: str) -> RemediationPlan:
    session = session_store.get(scan_id)
    with session.workflow_lock:
        return remediation_plan(session)


@app.put("/scans/{scan_id}/remediation")
def put_remediation_plan(
    scan_id: str,
    request: UpdateRemediationRequest,
) -> RemediationPlan:
    session = session_store.get(scan_id)
    return update_remediation_plan(
        session,
        request.included_finding_ids,
        request.ignored_finding_ids,
        request.plan_revision,
    )


@app.post("/scans/{scan_id}/remediation/generate")
def generate_remediation(
    scan_id: str,
    request: GenerateRemediationRequest,
) -> RemediationGenerationResponse:
    return generate_remediation_outputs(
        session_store.get(scan_id),
        expected_revision=request.plan_revision,
        output_mode=request.output_mode,
    )


@app.post("/scans/{scan_id}/reveal-findings")
def reveal_finding_values(
    scan_id: str,
    request: RevealFindingsRequest,
) -> RevealFindingsResponse:
    """Return exact values only after an authenticated, explicit user action."""

    session = session_store.get(scan_id)
    findings = session.findings(request.finding_ids)
    return RevealFindingsResponse(
        values=[
            RevealedFindingValue(finding_id=finding.id, value=finding.matched_text)
            for finding in findings
        ]
    )


@app.post("/scans/{scan_id}/open-file")
def open_session_file(scan_id: str, request: SessionOpenFileRequest) -> OpenFileResponse:
    session = session_store.get(scan_id)
    file_path = session_file_for_finding(session, request.finding_id)
    try:
        open_file(file_path)
    except OSError as error:
        raise SessionProblem(
            "file_unavailable",
            "The selected source file could not be shown in its folder. "
            "Check that it is still available.",
            410,
        ) from error
    return OpenFileResponse(status="ok")


@app.post("/scans/{scan_id}/open-output")
def open_redacted_copy(
    scan_id: str,
    request: OpenRedactedCopyRequest,
) -> OpenFileResponse:
    output_path = session_redacted_output_for_finding(
        session_store.get(scan_id),
        request.finding_id,
    )
    try:
        open_file(output_path)
    except OSError as error:
        raise SessionProblem(
            "file_unavailable",
            "The redacted copy could not be shown in its folder. Check that it is still available.",
            410,
        ) from error
    return OpenFileResponse(status="ok")


@app.delete("/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: str) -> Response:
    session_store.delete(scan_id)
    return Response(status_code=204)


# ---- Idle shutdown (one-click launcher mode) --------------------------------
#
# The launcher runs this server with no console window, so there's nothing
# visible to close. When REDACTLENS_IDLE_EXIT_MINUTES is set (launch.py sets it;
# `python -m redactlens_api` dev runs leave it unset = disabled), the process
# exits on its own once no request has arrived for that long. The frontend
# pings /health every few minutes, so the server stays up exactly as long as
# a RedactLens tab is open, then quietly goes away.

_IDLE_EXIT_MINUTES = float(os.environ.get("REDACTLENS_IDLE_EXIT_MINUTES", "0") or "0")
_last_request = time.monotonic()
_inflight = 0

if _IDLE_EXIT_MINUTES > 0:

    @app.middleware("http")
    async def _mark_activity(request, call_next):  # type: ignore[no-untyped-def]
        global _last_request, _inflight
        _inflight += 1
        try:
            return await call_next(request)
        finally:
            _inflight -= 1
            _last_request = time.monotonic()

    def _idle_watchdog() -> None:
        while True:
            time.sleep(30)
            idle = time.monotonic() - _last_request
            # Never exit mid-request: a long LLM scan can be quiet for longer
            # than the idle limit while still working.
            if _inflight == 0 and idle > _IDLE_EXIT_MINUTES * 60:
                os._exit(0)

    threading.Thread(target=_idle_watchdog, daemon=True).start()


# The frontend runs on Vite's dev server (a different port = a different
# origin to the browser, even though both are on this machine). CORS is added
# before the security boundary so SecurityBoundaryMiddleware remains the
# outermost layer and validates preflights before CORS can answer them.
app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(DEVELOPMENT_ORIGINS),
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", AUTH_HEADER],
)

# Added last so rejected traffic never reaches CORS, routing, or the optional
# activity middleware. Approved origins receive CORS headers on errors
# generated directly by this boundary, so the Vite UI can recover cleanly.
app.add_middleware(SecurityBoundaryMiddleware, security=launch_security)


# ---- Built frontend ----------------------------------------------------------
#
# Mounted last so every API route above wins. html=True serves index.html at
# "/". When packages/frontend/dist doesn't exist (dev checkouts that only use the Vite
# dev server, or a non-editable install), this is skipped and the API behaves
# exactly as before.


def _frontend_dist() -> Path:
    bundled = getattr(sys, "_MEIPASS", None)
    if getattr(sys, "frozen", False) and bundled:
        return Path(bundled).resolve() / "frontend" / "dist"
    return Path(__file__).resolve().parents[3] / "packages" / "frontend" / "dist"


class FrontendStaticFiles(StaticFiles):
    """Serve installed UI files without retaining an older WebView copy."""

    async def get_response(self, path: str, scope: Scope) -> Response:
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-store"
        return response


_DIST = _frontend_dist()
if (_DIST / "index.html").is_file():
    app.mount("/", FrontendStaticFiles(directory=_DIST, html=True), name="frontend")
