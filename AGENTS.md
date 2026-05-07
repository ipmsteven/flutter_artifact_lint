# flutter_artifact_lint

## Project Intent

Build a small Dart CLI that scans Flutter release artifacts, starting with iOS outputs, and tells the build pipeline whether the artifact can move to the next release step.

## Platform

- Runtime: Dart CLI
- First artifact target: Flutter iOS `.app`
- Later artifact targets: signed `.xcarchive`, signed `.ipa`, and Android APK/AAB

## Technical Direction

- Keep the CLI thin: argument parsing, output format, and exit policy only.
- Keep scanners artifact-oriented and deterministic where possible.
- Keep rules small and independently testable.
- Classify findings by confidence, not drama:
  - `failed`: deterministic artifact error
  - `warned`: risk evidence that needs review
  - `info`: artifact inventory

## Testing

- Default `dart test` must stay fast and use synthetic artifacts.
- Real Flutter build tests live under `integration_test/` and run explicitly.
- Add or update tests before behavior changes.
