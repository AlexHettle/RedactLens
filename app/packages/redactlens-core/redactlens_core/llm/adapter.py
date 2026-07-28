"""Local Ollama adapter -- the only "AI" anywhere in RedactLens, and strictly
optional.

Graceful degradation is mandatory (spec 4.4): every public method here
catches its own failures and returns None/False rather than raising, so an
Ollama outage degrades a scan to heuristics-only instead of breaking it.
The `except Exception` blocks below are a deliberate exception to
"don't catch broad exceptions" -- we genuinely cannot enumerate every way a
local HTTP call to a model server can fail (connection refused, timeout,
missing model, a differently-shaped response across ollama-python versions,
malformed JSON from the model itself), and the spec requires this boundary
to never take down a scan.
"""

import json
import math
import os
import re
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

import httpx
import ollama

# A small instruct model is the documented default (spec 4.4); override via
# constructor arg or this env var to point at whatever you've actually
# pulled (`ollama list`), without touching code.
DEFAULT_MODEL = os.environ.get("REDACTLENS_OLLAMA_MODEL", "llama3.2")
DEFAULT_HOST = "http://127.0.0.1:11434"
# Confirmed by testing: a real 30B-class model can take >15s to load from
# cold (Ollama unloads idle models after a few minutes by default). Ollama
# also serializes requests to one model, so one slow cold-start call causes
# every subsequent judge() call in the same scan to queue behind it and
# time out too -- a 15s default silently zeroed out an entire scan's worth
# of LLM findings. 60s gives real local models room to load once per scan.
DEFAULT_TIMEOUT = 60.0  # seconds
OllamaAvailability = Literal["unavailable", "model_missing", "ready"]

_SYSTEM_PROMPT = (
    "You are a careful, conservative sensitive-data reviewer. Respond with "
    "ONLY a single JSON object, no other text, of the exact form "
    '{"is_sensitive": <bool>, "confidence": <number 0 to 1>, "reason": <short string>}.'
)
_LOCAL_OLLAMA_HOSTS = frozenset({"127.0.0.1", "::1"})
_MODEL_DIGEST = re.compile(r"(?:sha256:)?[0-9a-f]{64}", flags=re.ASCII | re.IGNORECASE)


@dataclass(frozen=True)
class LLMVerdict:
    is_sensitive: bool
    confidence: float  # 0.0-1.0; the model's estimate that this IS sensitive
    reason: str


@dataclass(frozen=True)
class OllamaModelInfo:
    """Exact server identity for the model used by a measured evaluation."""

    name: str
    digest: str | None
    size: int | None = None


class OllamaAdapter:
    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        host: str = DEFAULT_HOST,
        timeout: float = DEFAULT_TIMEOUT,
        options: dict[str, int | float] | None = None,
    ):
        verified_host = _verified_loopback_host(host)
        self.model = model
        self.options = dict({"temperature": 0} if options is None else options)
        self._verified_host = verified_host
        self._timeout = timeout
        # The prompt may contain raw matches, surrounding source text, and a
        # selected file path. Do not let environment proxy variables or an HTTP
        # redirect move that request away from the verified loopback peer.
        self._client = ollama.Client(
            host=verified_host,
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
        )

    def available(self) -> bool:
        """True only if Ollama is reachable AND the configured model is
        actually pulled -- a reachable server with the wrong/missing model
        would otherwise silently degrade every judge() call to None while
        claiming llm_used=True."""
        return self.available_model() is not None

    def availability_status(self) -> OllamaAvailability:
        """Distinguish an unreachable Ollama service from a missing model."""
        models = self.local_models()
        if models is None:
            return "unavailable"
        configured_model = self.matching_model_info(models)
        return "ready" if configured_model is not None else "model_missing"

    def local_models(self) -> list[OllamaModelInfo] | None:
        """Return locally runnable models, excluding Ollama cloud references.

        ``None`` means the local Ollama service could not be reached. An empty
        list means Ollama is reachable but no eligible local model is installed.
        """
        try:
            response = self._client.list()
        except Exception:
            return None
        by_name = {}
        for info in _model_infos(response):
            if not _is_verified_local_model(info):
                continue
            details = self._raw_model_details(info.name)
            if not isinstance(details, dict) or _has_remote_model_reference(details):
                continue
            by_name[info.name] = info
        return sorted(by_name.values(), key=lambda info: info.name.casefold())

    def _raw_model_details(self, model: str) -> dict[str, object] | None:
        """Read unfiltered ``/api/show`` JSON and fail closed on any error.

        ollama-python 0.6.x does not expose Ollama's ``remote_host`` and
        ``remote_model`` response fields, so its typed ``show()`` result cannot
        establish that a renamed model is local. Inspecting the raw response
        preserves those authoritative fields before any source text is sent.
        """

        try:
            with httpx.Client(
                base_url=self._verified_host,
                timeout=self._timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = client.post("/api/show", json={"model": model})
                response.raise_for_status()
                payload = response.json()
        except Exception:
            return None
        return payload if isinstance(payload, dict) else None

    def matching_model_info(
        self,
        models: list[OllamaModelInfo],
    ) -> OllamaModelInfo | None:
        """Resolve the configured model against a previously fetched inventory."""
        return next(
            (info for info in models if _model_matches(self.model, info.name)),
            None,
        )

    def available_model(self) -> str | None:
        """Return the server's exact matching model name, including its tag."""
        info = self.available_model_info()
        return info.name if info is not None else None

    def available_model_info(self) -> OllamaModelInfo | None:
        """Return the exact matching server model name and immutable digest."""
        models = self.local_models()
        if models is None:
            return None
        return self.matching_model_info(models)

    def judge(self, question: str) -> LLMVerdict | None:
        """Ask the local model a yes/no-ish sensitivity question. Returns
        None on any failure -- unavailable, timeout, or a response that
        doesn't parse into the expected shape."""
        try:
            response = self._client.generate(
                model=self.model,
                system=_SYSTEM_PROMPT,
                prompt=question,
                format="json",
                stream=False,
                options=self.options,
            )
        except Exception:
            return None

        raw = _response_text(response)
        if not raw:
            return None
        try:
            parsed = json.loads(raw)
            is_sensitive = parsed["is_sensitive"]
            confidence = parsed["confidence"]
            if not isinstance(is_sensitive, bool):
                return None
            if (
                not isinstance(confidence, (int, float))
                or isinstance(confidence, bool)
                or not math.isfinite(confidence)
                or not 0.0 <= confidence <= 1.0
            ):
                return None
            return LLMVerdict(
                is_sensitive=is_sensitive,
                confidence=float(confidence),
                reason=str(parsed.get("reason", ""))[:300],
            )
        except (json.JSONDecodeError, KeyError, TypeError):
            return None


def _response_text(response: object) -> str | None:
    """ollama-python has returned both dict-like and attribute-style
    response objects across versions; handle either."""
    if isinstance(response, dict):
        return response.get("response")
    return getattr(response, "response", None)


def _model_names(response: object) -> list[str]:
    return [info.name for info in _model_infos(response)]


def _model_infos(response: object) -> list[OllamaModelInfo]:
    models = (
        response.get("models", [])
        if isinstance(response, dict)
        else getattr(response, "models", [])
    )
    infos = []
    for m in models:
        name = (
            m.get("model") or m.get("name")
            if isinstance(m, dict)
            else getattr(m, "model", None) or getattr(m, "name", None)
        )
        if name:
            digest = m.get("digest") if isinstance(m, dict) else getattr(m, "digest", None)
            raw_size = m.get("size") if isinstance(m, dict) else getattr(m, "size", None)
            size = (
                int(raw_size)
                if isinstance(raw_size, (int, float))
                and not isinstance(raw_size, bool)
                and math.isfinite(raw_size)
                and raw_size >= 0
                else None
            )
            infos.append(
                OllamaModelInfo(
                    name=str(name),
                    digest=str(digest) if digest else None,
                    size=size,
                )
            )
    return infos


def _is_cloud_model(value: str) -> bool:
    """Identify Ollama cloud-only tags so local-only scans cannot select them."""
    reference = _split_model_reference(value)
    if reference is None:
        return False
    _base, tag = reference
    if tag is None:
        return False
    normalized_tag = tag.casefold()
    return normalized_tag == "cloud" or normalized_tag.endswith("-cloud")


def _is_verified_local_model(info: OllamaModelInfo) -> bool:
    """Accept only inventory entries backed by verifiable local weight bytes.

    Ollama cloud references appear in ``/api/tags`` and can be copied to an
    innocent-looking alias, so the model name alone is not a sufficient local
    execution boundary. Local models have a positive on-device size and a
    content digest; cloud references report no local weight bytes.
    """

    return (
        not _is_cloud_model(info.name)
        and info.size is not None
        and info.size > 0
        and info.digest is not None
        and _MODEL_DIGEST.fullmatch(info.digest) is not None
    )


def _has_remote_model_reference(details: dict[str, object]) -> bool:
    """True when Ollama identifies a model as backed by a remote service."""

    return any(details.get(field) not in (None, "") for field in ("remote_host", "remote_model"))


def _verified_loopback_host(host: str) -> str:
    """Return a canonical numeric-loopback Ollama URL or fail closed."""

    if not isinstance(host, str) or host != host.strip():
        raise ValueError("Ollama host must be a numeric loopback HTTP URL")
    parsed = urlsplit(host)
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("Ollama host must use a valid loopback port") from error
    if (
        parsed.scheme != "http"
        or parsed.hostname not in _LOCAL_OLLAMA_HOSTS
        or port is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise ValueError("Ollama host must be a numeric loopback HTTP URL")
    authority = f"[{parsed.hostname}]" if parsed.hostname == "::1" else parsed.hostname
    return f"http://{authority}:{port}"


def _model_matches(configured: str, available: str) -> bool:
    """Match exact tags; an omitted tag means only the conventional ``latest``.

    Treating every tag of one base name as interchangeable can silently run a
    different model (for example ``:1b`` instead of ``:3b``). Ollama resolves
    an omitted tag as ``latest``, so that is the only safe implicit alias.
    """
    configured_reference = _split_model_reference(configured)
    available_reference = _split_model_reference(available)
    if configured_reference is None or available_reference is None:
        return False
    configured_base, configured_tag = configured_reference
    available_base, available_tag = available_reference
    if available_tag is None:
        return False
    if configured == available:
        return True
    return (
        configured_tag is None and available_tag == "latest" and configured_base == available_base
    )


def _split_model_reference(value: str) -> tuple[str, str | None] | None:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(character.isspace() for character in value)
    ):
        return None
    separator_index = value.rfind(":")
    # A colon before the final slash belongs to a registry host/port, not a tag.
    if separator_index <= value.rfind("/"):
        return (value, None)
    base = value[:separator_index]
    tag = value[separator_index + 1 :]
    if not base or not tag:
        return None
    return (base, tag)
