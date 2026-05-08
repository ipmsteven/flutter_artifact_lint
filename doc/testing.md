# Testing

This document describes the main automated tests used by
`flutter_artifact_lint`, especially the macOS-only end-to-end tests that build
real iOS binaries.

## Fast Tests

Run the Dart test suite on any supported development machine:

```bash
dart test
```

These tests cover CLI behavior, baseline handling, rule classification,
privacy manifest validation, evidence mapping, and synthetic Mach-O parser
fixtures.

## iOS E2E Requirements

The iOS E2E tests require:

- macOS
- Flutter on `PATH`
- Xcode command line tools
- `xcodebuild`
- `xcrun`

Tests skip themselves when the required local toolchain is unavailable.

## Core iOS E2E

Run the core E2E suite:

```bash
dart test integration_test/flutter_ios_build_e2e_test.dart integration_test/macho_objc_toolchain_e2e_test.dart integration_test/macho_swift_toolchain_e2e_test.dart --reporter expanded
```

`flutter_ios_build_e2e_test.dart` creates a real Flutter iOS app, injects a
placeholder camera purpose string, runs
`flutter build ios --release --no-tree-shake-icons --no-codesign`, and verifies
that the CLI fails the artifact with `ios.permission.camera.empty`. It also
checks that Mach-O architecture and build-version metadata are reported from
the compiled app.

`macho_objc_toolchain_e2e_test.dart` compiles a real Objective-C fixture with
`xcrun clang` and verifies that the Mach-O parser reads Objective-C classes,
protocols, methods, selectors, ivars, and properties from the binary.

`macho_swift_toolchain_e2e_test.dart` compiles real Swift and Objective-C
fixtures with `xcrun swiftc` and `xcrun clang`. It verifies Swift nominal type,
field, protocol, and protocol-conformance metadata, plus Objective-C superclass
metadata.

## Flutter Plugin Matrix E2E

The plugin matrix creates temporary Flutter iOS apps, adds real pub.dev
packages, builds unsigned release `.app` artifacts, and scans the resulting
binaries. Use `FAL_PLUGIN_MATRIX_SHARD` to run one shard locally:

```bash
FAL_PLUGIN_MATRIX_SHARD=permissions-a dart test integration_test/flutter_ios_plugin_matrix_e2e_test.dart --reporter expanded
FAL_PLUGIN_MATRIX_SHARD=permissions-b dart test integration_test/flutter_ios_plugin_matrix_e2e_test.dart --reporter expanded
FAL_PLUGIN_MATRIX_SHARD=platform dart test integration_test/flutter_ios_plugin_matrix_e2e_test.dart --reporter expanded
FAL_PLUGIN_MATRIX_SHARD=ecosystem dart test integration_test/flutter_ios_plugin_matrix_e2e_test.dart --reporter expanded
```

Omit `FAL_PLUGIN_MATRIX_SHARD` to run all plugin scenarios sequentially:

```bash
dart test integration_test/flutter_ios_plugin_matrix_e2e_test.dart --reporter expanded
```

The current scenarios are:

| Scenario | Shard | Packages | Expected scanner coverage |
| --- | --- | --- | --- |
| `camera-media` | `permissions-a` | `camera`, `image_picker`, `photo_manager` | Camera and photo-library permission evidence without matching purpose strings. |
| `location-contacts` | `permissions-a` | `geolocator`, `flutter_contacts` | Location and contacts permission evidence without matching purpose strings. |
| `notification-auth` | `permissions-b` | `flutter_local_notifications`, `local_auth` | Notification evidence and Face ID permission evidence without a matching purpose string. |
| `bluetooth-speech` | `permissions-b` | `flutter_blue_plus`, `speech_to_text` | Bluetooth and microphone permission evidence without matching purpose strings. |
| `required-reason-storage` | `platform` | `shared_preferences`, `path_provider`, `device_info_plus` | Required-reason disk-space API evidence without a matching privacy manifest category. |
| `webview-url` | `platform` | `webview_flutter`, `url_launcher` | Dynamic-code or dynamic-loading evidence while asserting that `UIWebView` is not reported for this modern WebKit stack. |
| `permission-handler` | `ecosystem` | `permission_handler` | Permission-handler macros compiled into the iOS binary for camera, contacts, location, photos, bluetooth, microphone, and notification evidence. |
| `firebase-notification` | `ecosystem` | `firebase_core`, `firebase_messaging` | Firebase messaging notification evidence. |
| `comprehensive-all` | `ecosystem` | All packages above | Combined app-level coverage across permissions, notification evidence, Face ID, required-reason disk-space evidence, and Mach-O metadata. |

The `permission_handler` scenarios inject the plugin's documented iOS
preprocessor macros into the generated Podfile before building. This is
intentional: without those macros, `permission_handler` compiles many iOS
permission implementations out of the binary, so the scanner should not report
those permissions.

## CI Layout

GitHub Actions runs fast Dart checks on Ubuntu and iOS E2E checks on macOS.
The macOS job is split into five parallel shards:

- `ios-e2e-shard (core)`
- `ios-e2e-shard (permissions-a)`
- `ios-e2e-shard (permissions-b)`
- `ios-e2e-shard (platform)`
- `ios-e2e-shard (ecosystem)`

The protected branch check is `ios-e2e`. It is an aggregate job that passes only
after every macOS shard succeeds. This keeps branch protection stable while
letting the expensive Flutter/iOS matrix run in parallel.

## Release Verification

Before publishing, run:

```bash
dart format --set-exit-if-changed lib test integration_test bin
dart analyze
dart test
dart test integration_test
dart pub publish --dry-run
```

For faster local iteration, run the shard commands above instead of the whole
`integration_test` directory.
