# Release Checklist

Use this checklist for every pub.dev release.

## Prepare

1. Update `version` in `pubspec.yaml`.
2. Update `CHANGELOG.md` with user-facing changes.
3. Confirm `README.md` and `doc/rules.md` describe the released behavior.
4. Open a pull request and wait for the required GitHub checks:
   - `dart`
   - `ios-e2e`
5. Merge the pull request after the checks pass.

## Verify

Run the local release checks from `main`:

```bash
dart format --set-exit-if-changed lib test integration_test bin
dart analyze
dart test
dart test integration_test
dart pub publish --dry-run
```

`dart pub publish --dry-run` must report `Package has 0 warnings.`

## Publish

Publish the package:

```bash
dart pub publish
```

After pub.dev accepts the upload, create and push the matching git tag:

```bash
git tag v<version>
git push origin v<version>
```

Then create a GitHub release for the tag and link to the pub.dev package page.

## After Release

1. Confirm the package page is visible on pub.dev.
2. Confirm the GitHub release points to the correct tag.
3. Confirm `main` is clean and tracks `origin/main`.
4. Start the next change from a new branch.
