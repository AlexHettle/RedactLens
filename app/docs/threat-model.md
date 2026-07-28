# RedactLens local threat model

Last reviewed: 2026-07-27

## Scope and security objective

RedactLens reads files that may contain credentials, personal identifiers, financial records, and
other sensitive values. Its security objective is to keep that data on the device, restrict
browser-initiated filesystem actions to the intended RedactLens UI, and make malformed input fail
within explicit resource boundaries.

RedactLens is a local review tool, not a sandbox, antivirus engine, access-control system, or proof
that a file contains no sensitive information. It assumes the operating-system account running it
is trusted enough to read the selected files.

## Sensitive assets

The primary assets are:

- raw file and document contents;
- user-supplied literal and description targets;
- detector source context and local Ollama prompts;
- trusted finding offsets and raw matches;
- selected roots, source paths, and generated output paths;
- remediation decisions and generated redacted copies;
- the per-process launch capability; and
- local diagnostic files.

Rewrite offsets, source context, model prompts, and free-form model explanations remain inside the
Python process. Model explanations are treated as untrusted because they can repeat source text;
description-target findings use fixed public guidance instead. The browser normally receives
redacted public findings. Only an authenticated, bounded, explicit full-value request can return
raw matches for server-owned IDs from a completed scan; the UI keeps those values out of scan
state, reports, notifications, and persisted settings and clears them when hidden. Reports are
constructed from nested field allowlists and use selected-root-relative paths.

## Trust boundaries

```text
Untrusted website / browser origin
          |
          | outer Host + Origin/Sec-Fetch-Site + launch-token checks
          | (before CORS, routing, or mutation-body acceptance)
          v
RedactLens FastAPI process on 127.0.0.1
          |
          | bounded public request -> trusted ephemeral session
          v
redactlens-core + local filesystem + optional local Ollama
```

The React UI is trusted to request actions, but not to supply trusted file coordinates or raw
matches. The API resolves every remediation and file-reveal operation through its server-owned scan
session. The core and API process are trusted with raw contents because scanning cannot occur
without reading them.

The network boundary is loopback HTTP only. No cloud service receives scan data during supported
operation. Ollama is configured at `http://127.0.0.1:11434` by default. Its client rejects
non-numeric or non-loopback hosts, ignores proxy environment variables, and refuses redirects.
Model inventory is fail-closed: a selectable model must have a valid content digest and positive
local weight size. Before source text is sent, RedactLens inspects the unfiltered local
`/api/show` response and rejects a model if `remote_host` or `remote_model` is present.
Cloud-tagged and zero-size aliases are also excluded.

## Browser and localhost threats

### Localhost request forgery

A hostile website can attempt to send forms, fetches, or image requests to a service listening on
localhost. Binding to `127.0.0.1` does not prevent that by itself.

Controls:

- every API process generates a new random 32-byte launch capability;
- every POST, PUT, PATCH, and DELETE requires that capability in `X-RedactLens-Token`;
- the frontend obtains it through `GET /launch-session` and retains it only in module memory;
- the capability is never placed in URLs, storage, React state, reports, or logs;
- browser `Origin` is restricted to the same loopback origin or the explicit Vite development
  origins on port 5173;
- requests without `Origin` are rejected when `Sec-Fetch-Site` identifies them as cross-site;
- the security boundary wraps CORS, so a forged Host or Origin cannot obtain a successful
  preflight before authorization checks run;
- CORS permits only the two explicit development origins and the required headers/methods; and
- Vite uses strict port 5173 so it cannot silently move to an origin the API did not authorize.

Application responses and production and Vite-preview UI documents set a restrictive Content
Security Policy. Production scripts, stylesheet resources, images, forms, and browser connections
are limited to the local application origin; the bounded progress-width style attribute remains
allowed; objects and base-URL changes are disabled; framing is denied.
Development permits only the inline React Refresh bootstrap and loopback hot-reload WebSockets.
`X-Frame-Options: DENY` remains as a compatibility control. A hostile page cannot frame RedactLens
and use clickjacking to turn the trusted user's pointer or keyboard input into an authorized
action.

### Ollama transport and cloud-model confusion

The model prompt contains raw source context, so merely intending to call localhost is
insufficient. Controls:

- ambiguous detector prompts contain the exact candidate, its source path, and at most 100
  characters of surrounding text on each side; description targets inspect at most the first 40
  nonblank lines, skip physical lines over 16,384 characters, and submit one accepted line at a
  time;
- the production host is the numeric loopback address `127.0.0.1`;
- constructor validation rejects DNS names, non-loopback IPs, HTTPS endpoints, credentials,
  paths, queries, and fragments;
- the HTTP client uses `trust_env=False`, so `HTTP_PROXY`, `HTTPS_PROXY`, and related variables
  cannot intercept the request;
- redirects are disabled, so a loopback endpoint cannot forward a prompt body elsewhere;
- cloud-tagged model names are excluded;
- every accepted inventory item must report a valid content digest and a positive local byte size,
  preventing Ollama's zero-size cloud references from being accepted after an innocent-looking
  rename;
- every accepted model's unfiltered `/api/show` response must omit `remote_host` and
  `remote_model`; and
- RedactLens calls generation only and supplies no web-search tools.

The local Ollama process remains inside the trusted computing base. A malicious or compromised
process running as the signed-in user can lie about model inventory or transmit data independently,
just as it can read the selected source files directly. Defending against that same-user compromise
is outside RedactLens's supported boundary.

The launch-session response is protected by the browser same-origin policy and the same Host,
Origin, and fetch-site checks. A request that cannot read that response cannot construct the
required mutation header.

### DNS rebinding and forged Host headers

An attacker-controlled hostname resolving to loopback could otherwise make requests appear
same-origin to an attacker page.

Controls:

- `Host` must exactly match `127.0.0.1:<port>`, `localhost:<port>`, or `[::1]:<port>`;
- hostname case is normalized, while user info, suffixes, unbracketed IPv6, missing/extra
  separators, leading-zero ports, and noncanonical authorities are rejected;
- the port must be in RedactLens's explicit 8000–8010 API range; and
- same-origin `Origin` validation is derived from that validated loopback Host.

### Oversized or malformed browser requests

Controls:

- mutation bodies are streamed into a bounded 256 KiB buffer even when `Content-Length` is
  absent;
- a declared oversized body is rejected before it is read;
- browser scan requests allow at most 64 paths, 32 categories, and 100 user targets;
- path, category, target, and finding-ID strings have explicit length limits;
- remediation updates allow at most 5,000 included-plus-ignored finding IDs; and
- validation responses expose declared schema field names only, never undeclared client keys,
  rejected values, list indexes, parser offsets, or Pydantic input echoes.

Malformed non-ASCII launch-token headers take the same privacy-safe 403 path as any other invalid
capability. The live token is excluded from `LaunchSecurity` and middleware representations so an
ordinary configuration diagnostic cannot disclose it.

`REDACTLENS_MAX_REQUEST_BYTES` can lower or raise the body limit for a controlled local deployment.
Invalid or non-positive values fall back to 256 KiB.

## Ephemeral session lifecycle

The API retains active workflow state and, for successfully completed scans, trusted findings,
source fingerprints, remediation state, generated-output metadata, and bounded SSE history in a
process-local `ScanSession`. The browser receives only the public projection and submits opaque
scan/finding IDs for follow-up actions. Every public snapshot includes the exact `event_cursor`
already incorporated into it. The bounded SSE log rejects a cursor older than its retained window
by closing the stream, forcing authoritative snapshot recovery; terminal streams perform one final
event drain before closing.

The store applies retained-session count and estimated-byte limits at pending creation, during
active event growth, at job finalization, and after remediation or generated-output metadata
changes. Retained-state admission and growth evict only terminal sessions. If active work already
occupies all available retained count or byte capacity, RedactLens rejects a new scan instead of
capacity-evicting an active one. If an active job's own or aggregate event growth cannot fit,
RedactLens immediately clears its variable session-owned sensitive state and raises a capacity
failure to the still-attached worker, which records a bounded terminal `session_capacity` result.

Background-worker slots are tracked independently from retained sessions under the same configured
maximum. `create_pending` reserves a slot before returning, so admission cannot race through the
gap before `start_job`. A hard-retention deadline may remove an active session and clear all of its
session-owned references while a noninterruptible worker remains alive. That worker may retain
transient request or source data in its call stack until the blocking operation returns; Python
threads cannot be safely killed. The worker's registry slot survives cleanup, and further admission
is rejected until the thread actually exits and unregisters. Thus terminal eviction or
hard-retention cleanup can free retained-session memory without being mistaken for permission to
start another worker. An interrupted core coordinator also cancels queued file futures and waits
for already-running nested file workers before it emits a terminal event or lets the registered
top-level worker exit, so the slot covers nested work for the scan's full lifetime.

Idle expiry normally applies after a session becomes terminal. A live active job is exempt from
that terminal idle window only until a hard retention deadline derived from the job timeout and
the longest bounded extraction/model operation. Core progress events and every live SSE polling
cycle refresh access and LRU ordering but cannot extend the hard deadline. Pending sessions without
a worker expire from creation time, dead nonterminal workers are removed, and thread-start failure
clears the pending session immediately. Hard-deadline and orphan cleanup are separate from capacity
eviction and may remove nonterminal sessions that can no longer be safely retained. They cannot
forcibly stop a third-party blocking call; that thread may continue consuming resources and retain
transient scan working data until it returns, but its independent slot keeps the number of
pending/live workers within the configured bound. A truly nonreturning nested operation can hold
its top-level slot and working data indefinitely. If enough slots are stuck, new scans are denied
until one returns; this is a bounded availability and in-process retention risk, not a path for
expired scans to orphan nested threads while replacements accumulate.

Phase 5 intentionally distinguishes cancellation from cleanup. `DELETE` requests cooperative
cancellation for an active scan. Every cancelled, timed-out, or failed summary is normalized to its
actual status with `incomplete: true`. Its redacted public partial findings remain inspectable when
capacity permits, but raw internal findings, fingerprints, remediation state, generated-output
state, and request data are cleared, so it cannot authorize remediation or file reveal. `DELETE`
on a terminal scan removes it immediately. Terminal expiry, terminal deletion, terminal capacity
eviction, and shutdown clear all remaining session references.

Before remediation review or either report export, the results UI requests the authoritative plan
again. The API revalidates generated-output fingerprints, and the UI reconciles cached output
evidence against the exact returned revision. Conflict, deletion, expiry, or refresh failure
creates no report. Results operations are serialized against plan mutations and fenced to the
originating scan, so a late response from an abandoned result cannot reset or download into a newer
workflow. This is point-in-time evidence; another trusted local process can still alter a file
after the response.

## Filesystem threats

### Forged paths and write requests

Browser requests cannot submit remediation source paths, output paths, offsets, or raw values. They
submit finding IDs, and the API resolves those through the ephemeral session. The full-value route
is a capability-authenticated POST with at most 250 IDs per request and returns no offsets or source
context. File reveal is similarly restricted to a known finding and a current
fingerprint-verified source, or to a current fingerprint-verified generated output. The historical
route names do not launch content: the Windows application only selects the file in Explorer.

Source and generated-output fingerprints detect changes before a write, regeneration, or trusted
reveal operation. Atomic sibling-file replacement prevents a failed write from leaving a partial
final output.

### Filesystem redirects and non-regular entries

RedactLens makes selected paths lexically absolute without dereferencing the selected entry. It does
not follow file or directory symbolic links during discovery. A selected link or a link found under
a selected directory becomes an explicit skipped-file result. Directory links are removed from
the checkpointed top-down `scandir` walk before descent. Retained directories are revalidated
immediately before enumeration, preventing link loops and traversal beyond the selected root.

Windows junctions and all other detected reparse-point redirects receive the same conservative
no-traversal treatment. FIFOs, devices, sockets, and other non-regular entries are rejected before
any read, preventing a selected named pipe from blocking a scan indefinitely. File reads and API
fingerprints open only an already-classified regular entry, request no-follow behavior where the
platform exposes it, and compare pre-open metadata with the opened descriptor's identity. Every
lexical parent component is checked too, so a regular final filename below a redirecting ancestor
is refused by core, CLI, and API workflows. Internal fingerprints retain device, inode, size,
nanosecond modification time, nanosecond change time, and SHA-256. Public responses do not expose
the added device, inode, or change-time identity fields.

Redacted-copy output names are constructed lexically. Atomic writes reject redirecting or
non-directory parents before staging and recheck the parent chain before publication, verification,
cleanup, and rollback. Existing final entries must still be unchanged regular files. A malicious
same-user process can race between remaining operating-system calls, which stays an explicit
residual risk.

The UI groups symbolic-link skips as **Symbolic links** and tells the user to select the real target
only after confirming that location is trusted. Other redirect and special-entry refusals retain
stable skip codes and curated reasons.

### Root ignore policy

`.redactlensignore` is untrusted scan-root control data. RedactLens reads it only when it is a stable,
ordinary file and refuses symbolic links and reparse points. It is limited to 1,000,000 bytes,
1,024 rules, 1,024 characters in one pattern, and 65,536 pattern characters in total. Its `*`,
`**`, and `?` matching uses bounded, backtracking-safe segment expressions. Invalid UTF-8 or any
resource-limit violation disables the complete ignore matcher and scans all candidates; RedactLens
never keeps a partial prefix that could omit a late re-inclusion rule. Legitimate rule expressions
remain visible in skip explanations by design, but a linked out-of-root control file is never read
or projected.

### Time-of-check/time-of-use changes

Fingerprint comparisons cover device, inode, size, nanosecond modification/change times, and
SHA-256 content. They detect ordinary changes and identical-content entry replacement during and
after scanning. Large-text probing carries that entry snapshot into the streaming pass; the second
no-follow descriptor cannot establish a replacement as a new baseline. Streaming enforces the byte
ceiling on descriptor metadata and every read, then rechecks descriptor, final-path, and ancestor
identity after EOF. Growth beyond the ceiling becomes `file_too_large`; any other between-pass or
in-pass change becomes a stable read-failure skip, and findings from that unstable read are
discarded.

Remediation opens each retained source once through a no-follow descriptor, checks the size and
SHA-256 against the retained fingerprint, and passes those exact captured bytes through rendering
and verification. Committed-output validation is also no-follow and bounded; rollback publishes a
new trusted identity only after the restored bytes and metadata verify. ZIP-aware output naming
uses a stable four-byte prefix read instead of materializing a document. RedactLens does not claim to
defeat a malicious same-user process racing entries between every operating-system call. Such a
process is inside the local-process trust boundary and can already read or modify the user's files.

### Compute and concurrency exhaustion

Independent files run within a bounded sliding worker window, while structured extraction has a
separate lower semaphore. The initial large-text encoding-validation pass and the later windowed
scan both retain one source identity, stop at the configured byte ceiling (reading at most one
redactlens byte beyond it to detect growth), and check cancellation, the whole-job deadline, and the
per-file extraction timeout around every bounded read. Streaming I/O and decoding are accounted
separately from detector CPU time. Local-model calls from all concurrent scans share one
process-wide execution gate, and a queued caller continues checking cancellation and job deadlines
before entering the model boundary.

Declarative detector expressions use the timeout-capable `regex` engine. Primary regex and entropy
patterns, context searches, and path-context searches have an engine-enforced 0.5-second call
deadline and a 512-entry compiled-pattern cache. Candidate generation additionally has a shared
100,000-candidate file budget across regex, entropy, keyword, and literal detectors and across all
streamed chunks, plus a 100,000-candidate budget per materialized or streamed window. A deadline or
candidate-cap violation becomes a structured skip for that file rather than trapping the scan
worker or growing an unbounded candidate collection. Active regex lookahead or lookbehind requires
a positive declared `max_lookaround_length`; that external dependency is added to streaming overlap
and an undeclared lookaround is rejected when the detector registry loads. The local profiler
applies the same real deadline to built-in or explicitly supplied configurable detector directories.

## Malicious documents and archives

XML document parts use `defusedxml` during extraction. Document write-back uses `lxml` with entity
resolution and network access disabled. Recognized extraction failures become skipped-file reasons
rather than aborting the scan.

ZIP, Office, and OpenDocument containers enforce:

| Boundary                                                  |               Default |
| --------------------------------------------------------- | --------------------: |
| Archive entries                                           |                10,000 |
| One decompressed member                                   |      10,000,000 bytes |
| Member compression ratio                                  |                 200:1 |
| Total decompression budget, shared across nested archives |      50,000,000 bytes |
| Nested ZIP depth                                          |              2 levels |
| Extracted document text                                   | 50,000,000 characters |
| PDF pages                                                 |                10,000 |

The container is rejected before unsafe content is read when it contains:

- an encrypted member;
- duplicate normalized or case-folded member paths;
- POSIX/backslash absolute, drive-qualified, or parent-traversal member paths, including any
  original internal `..` component before normalization;
- a member over the size or compression-ratio limit;
- declared total content over the decompression limit; or
- nesting beyond the configured depth.

The nested budget charges both an embedded archive's bytes and the members read inside it. This is
intentional: otherwise many individually valid nested archives could multiply total memory and
CPU work. RedactLens never extracts archive members to filesystem paths during scanning. A
safety-limit violation rejects the containing input with a specific reason; an ordinary corrupt
embedded document is isolated so unrelated members can still be scanned.

Document text is charged incrementally before `_SegmentBuilder` retains another segment. The same
segment boundary checks cancellation and the per-file extraction deadline. PDFs are refused with
`document_limit` before page 10,001 is extracted, and the control boundary is also checked before
and after each accepted page. PDF page text additionally passes through pypdf's visitor callback,
which checks the remaining character budget while pypdf emits text; at the directly scanned file
boundary, exceeding it becomes `extracted_text_too_large`. A directly scanned PDF whose pages
produce no extractable text becomes `no_extractable_text` with an explicit OCR-required reason
rather than a successful empty scan. PDF
findings remain read-only, and standalone images still require separate trusted OCR. Unsupported
archive formats are treated as binary or unsupported inputs rather than passed to an external
extractor.

## Diagnostics and error handling

Reusable diagnostics never record request bodies, authorization headers, request URLs, raw
matches, source context, report contents, or Ollama prompts. Uvicorn access logging is disabled in
both launcher and development entry points. Expected workflow failures use stable structured error
codes and curated messages. Filesystem skips do not reuse raw `OSError` text, and validation
failures do not echo rejected input or undeclared keys.

Unexpected API failures return only:

```json
{
  "error": {
    "code": "internal_error",
    "message": "RedactLens could not complete that request."
  }
}
```

The local diagnostic stack contains call sites but deliberately omits the exception message and
local-variable values. In the console-less launcher this goes to `redactlens-launcher.log`; in a
development run it remains in the local terminal. Launcher startup failures may include ordinary
startup diagnostics, but scanning request bodies and the launch capability are never logged.

## Local-process threats and residual risk

RedactLens does not defend against another process running as the same operating-system user. Such a
process can generally read the same source files, inspect process memory, call the loopback API,
or modify outputs directly. The launch capability is designed to stop remote websites, not local
malware or an actively hostile account owner.

Other residual risks include:

- parser vulnerabilities in Python or third-party document libraries despite the surrounding
  limits; the incremental text and pypdf callback budgets bound what RedactLens retains but cannot
  prevent every transient allocation inside a parser before it invokes RedactLens's callback;
- native or third-party extraction and file-read calls cannot be forcibly interrupted in the
  middle of one blocking call—including one pypdf page parse—although the next checkpoint enforces
  cancellation and time budgets;
- secrets encoded in unsupported formats, images, encrypted files, steganography, or patterns no
  detector recognizes;
- races performed by another trusted-local process after a fingerprint check;
- file-manager or operating-system vulnerabilities after a trusted reveal, and a user's later
  choice to open active content manually;
- a generated report becoming stale if a trusted local process changes disk state after its
  authoritative freshness response;
- browser extensions with permission to inspect the RedactLens page; and
- sensitive filenames or full paths shown on demand in the trusted local UI.

These limitations are why RedactLens consistently describes results as a review aid and never as a
guarantee that a user or file is safe.
