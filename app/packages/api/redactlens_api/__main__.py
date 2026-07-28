"""`python -m redactlens_api` -- always binds to 127.0.0.1, never 0.0.0.0."""

import sys

import uvicorn

if __name__ == "__main__":
    if sys.platform != "win32":
        raise SystemExit("RedactLens supports Microsoft Windows only.")
    uvicorn.run("redactlens_api.main:app", host="127.0.0.1", port=8000, access_log=False)
