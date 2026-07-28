# RedactLens privacy policy

Effective date: July 27, 2026

RedactLens is a local-first desktop application. The official RedactLens application does not
require an account and does not collect, transmit, sell, or share scanned file contents or personal
information with the RedactLens maintainers.

## What the application processes

RedactLens processes the files and folders that the user explicitly selects. It may temporarily
hold file contents, findings, file paths, and redaction choices in memory while a scan or review
session is active. That information is used only to provide the requested local scan and redaction
workflow.

The application does not include analytics, advertising, remote telemetry, hosted crash reporting,
or a RedactLens cloud service. Its local API binds only to the loopback interface.

## Optional local AI

When enabled, AI-assisted review is sent only to an Ollama service reached through a numeric
loopback address on the same device. RedactLens does not honor proxy environment variables for
these requests and refuses HTTP redirects. It offers only model inventory entries that have a
content digest and a positive local weight size. Before any source text is sent, RedactLens also
inspects Ollama's unfiltered `/api/show` response and rejects models with a `remote_host` or
`remote_model`. Cloud-tagged, renamed cloud, zero-size, remotely backed, and otherwise
unverifiable model references are excluded.

For an ambiguous built-in detector match, the local-model prompt can contain the absolute source
path, the exact candidate value, and up to 100 characters of surrounding text on each side. A
plain-English custom rule sends the description supplied by the user and examines up to the first
40 nonblank lines of each file, one line at a time; a physical line longer than 16,384 characters
is skipped by that feature. These prompts and the model's responses remain within the local
RedactLens and Ollama processes during supported operation.

Ollama and installed models are separate software governed by their own terms and local
configuration. RedactLens trusts the locally running Ollama process and the signed-in operating
system account. Users who want an additional service-wide safeguard can disable Ollama cloud
features in Ollama's own configuration, but RedactLens does not require cloud access and never
invokes Ollama web-search functionality.

## Information stored on the device

RedactLens may store the following locally:

- appearance preferences, including theme and high-contrast choices;
- the selected local Ollama model;
- WebView application data needed to display the desktop interface;
- a local launcher diagnostic log containing technical startup and error information;
- user-created redacted copies, reports, or changes to original files; and
- short-lived recovery files used to make file replacement safer.

These items are not transmitted to the RedactLens maintainers. Diagnostic logs are designed to
exclude raw matched values, but users should still review any log before sharing it because local
paths and technical context may be sensitive.

Uninstalling RedactLens may not delete reports, redacted copies, intentionally replaced files, or
other documents the user created. Those remain under the user's control.

## External links

RedactLens includes user-initiated links to resources such as GitHub, Ollama, and model
documentation. Opening a link launches the user's browser. The destination site and browser may
process information under their own privacy policies; RedactLens does not control those services.

## Security

RedactLens is a review aid and cannot guarantee that every sensitive value will be found or that
every file is safe to share. Users should review findings and resulting files before disclosure.
See the [security policy](../../.github/SECURITY.md) and
the [threat model](../../app/docs/threat-model.md) for the supported
security boundary.

## Changes

Material changes to the application's data handling should be reflected in this file before a
release is published. The effective date above should be updated whenever those changes take
effect.

## Contact

Privacy questions may be submitted through the repository's issue tracker. Do not include real
credentials, personal records, private documents, or other sensitive values in a public issue.
