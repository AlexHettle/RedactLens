# Contributing to RedactLens

Thank you for helping improve RedactLens. Focused bug fixes, detector improvements, accessibility
work, tests, and documentation updates are welcome.

## Before opening a change

1. Search existing issues and pull requests for related work.
2. Describe the problem, expected behavior, and proposed scope.
3. Use fabricated examples only. Never submit real credentials, personal records, or private
   documents.
4. Keep changes focused and include tests for behavior changes.
5. Run the complete quality baseline:

   ```powershell
   .venv\Scripts\python.exe app\tooling\verify.py
   ```

Report suspected vulnerabilities privately according to [SECURITY.md](SECURITY.md), not through a
public issue or pull request.

## Contribution licensing

RedactLens uses an inbound-equals-outbound contribution policy:

- By submitting a contribution, you represent that you have the legal right to submit it.
- You agree that your contribution is licensed under the project's
  [MIT License](../LICENSE), without additional terms or restrictions.
- You retain copyright in your contribution.
- Do not submit third-party code, media, datasets, or other material unless its license permits
  inclusion and the required copyright, attribution, source, and license notices are included.
- Clearly identify code or assets derived from another project and describe any modifications.

No separate contributor license agreement is required unless the maintainers announce one before
accepting a contribution.

## Pull-request checklist

- [ ] The change is narrowly scoped and documented.
- [ ] New or changed behavior has meaningful tests.
- [ ] Fabricated fixtures cannot be mistaken for live credentials.
- [ ] Required third-party notices are included.
- [ ] `app\tooling\verify.py` passes.
