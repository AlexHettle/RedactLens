# RedactLens security policy

## Supported versions

Security fixes are provided for the latest published RedactLens release. Older versions may no
longer receive fixes, so users should reproduce a suspected issue with the newest release whenever
it is safe to do so.

## Report a vulnerability

Use the repository's **Security** tab and select **Report a vulnerability** to submit a private
report. Repository maintainers should enable GitHub private vulnerability reporting before the
first public release.

If private reporting is temporarily unavailable, open a minimal public issue asking the
maintainers to establish a private contact channel. Do not include exploit instructions, real
credentials, personal data, private file contents, or an unpatched vulnerability's sensitive
details in that issue.

A useful private report includes:

- the affected RedactLens version and Windows version;
- clear reproduction steps using fabricated data;
- the security impact and expected behavior;
- relevant logs with personal paths and values removed; and
- any suggested mitigation.

Maintainers should acknowledge a private report promptly, keep the reporter informed, and
coordinate disclosure after a fix or mitigation is available. Response times are best-effort and
may vary for a volunteer-maintained project.

## Security boundary

RedactLens is a local review aid, not a security sandbox or a guarantee that a file is safe to
share. It assumes the signed-in Windows account is trusted. It is not designed to protect against
a hostile local administrator, a compromised operating system, or every malformed or adversarial
document.

The application:

- binds its API to the loopback interface;
- does not intentionally upload selected files;
- masks finding values at the browser-facing boundary by default;
- uses opaque server-owned identifiers for file operations;
- re-verifies source files before writing changes; and
- requires explicit confirmation before replacing original files.

The detailed assets, trust boundaries, abuse cases, and residual risks are documented in the
[threat model](../app/docs/threat-model.md).

## Safe testing

Use only fabricated files and credentials in issues, tests, demonstrations, and pull requests.
Never test RedactLens against systems or data you do not own or have explicit permission to use.
