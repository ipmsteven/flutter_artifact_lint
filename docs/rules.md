# Rules

This document lists the public rule IDs emitted by `flutter_artifact_lint`.

## Baseline

`baseline.unused` reports a baseline entry that did not match any current finding.

## Failed

`ios.info_plist.missing` reports an app-like bundle without `Info.plist`.

`ios.info_plist.invalid` reports an `Info.plist` that cannot be parsed.

`ios.permission.camera.empty` reports an empty or placeholder camera purpose string.

`ios.permission.microphone.empty` reports an empty or placeholder microphone purpose string.

`ios.permission.photos.empty` reports an empty or placeholder photo library purpose string.

`ios.permission.contacts.empty` reports an empty or placeholder contacts purpose string.

`ios.permission.bluetooth.empty` reports an empty or placeholder bluetooth purpose string.

`ios.permission.face_id.empty` reports an empty or placeholder Face ID purpose string.

`ios.export_compliance.missing` reports a missing `ITSAppUsesNonExemptEncryption`.

`ios.launch_screen.missing` reports a missing launch storyboard or launch screen declaration.

`ios.orientations.missing` reports missing supported interface orientations.

`ios.ats.arbitrary_loads` reports a global ATS arbitrary-loads exception.

`ios.location.always_without_background_mode` reports always-location usage without the matching background mode.

`ios.privacy_manifest.invalid` reports an unparsable `PrivacyInfo.xcprivacy`.

`ios.privacy_manifest.invalid_accessed_api_types` reports an invalid `NSPrivacyAccessedAPITypes` shape.

`ios.privacy_manifest.missing_api_type` reports a required-reason entry without an API category.

`ios.privacy_manifest.empty_reasons` reports a required-reason entry without reason codes.

`ios.privacy_manifest.invalid_reason` reports a reason code that is not valid for the declared required-reason API category.

## Warned

`ios.permission.contacts.missing` reports contacts API evidence without `NSContactsUsageDescription`.

`ios.permission.camera.missing` reports camera API evidence without `NSCameraUsageDescription`.

`ios.permission.microphone.missing` reports microphone API evidence without `NSMicrophoneUsageDescription`.

`ios.permission.location.missing` reports location API evidence without a matching location purpose string.

`ios.permission.photos.missing` reports photo API evidence without a matching photo library purpose string.

`ios.permission.bluetooth.missing` reports bluetooth API evidence without `NSBluetoothAlwaysUsageDescription`.

`ios.permission.face_id.missing` reports Face ID API evidence without `NSFaceIDUsageDescription`.

`ios.notification.evidence` reports notification API or SDK evidence.

`ios.required_reason.user_defaults` reports UserDefaults evidence without a matching privacy manifest category.

`ios.required_reason.file_timestamp` reports file timestamp evidence without a matching privacy manifest category.

`ios.required_reason.disk_space` reports disk space evidence without a matching privacy manifest category.

`ios.required_reason.system_boot_time` reports system boot time evidence without a matching privacy manifest category.

`ios.required_reason.active_keyboards` reports active keyboard evidence without a matching privacy manifest category.

`ios.private_api.uiwebview` reports `UIWebView` evidence.

`ios.private_api.selector` reports private selector evidence.

`ios.private_api.framework` reports Mach-O load commands that link private Apple frameworks.

`ios.dynamic_code_execution.evidence` reports dynamic loading or script execution evidence.

## Info

`ios.bundle.identifier` reports the artifact bundle identifier.

`ios.bundle.version` reports the artifact version and build number.

`ios.bundle.nested` reports an app extension bundle found inside the app.

`ios.artifact.type` reports the scanned artifact type.

`ios.signing.unavailable` reports that signing state is unavailable for an unsigned artifact.

`ios.signing.present` reports that signing data appears to be present.

## Parser Coverage and Remaining Gaps

`test/string_scanner_gap_matrix_test.dart` documents parser acceptance cases and
remaining cases that the current string scanner intentionally does not cover
yet. The remaining gap cases are future parser acceptance targets.

Mach-O load-command evidence is parsed for thin and fat/universal binaries. The
parser currently reads `LC_LOAD_DYLIB`, `LC_LOAD_WEAK_DYLIB`,
`LC_REEXPORT_DYLIB`, `LC_LOAD_UPWARD_DYLIB`, and `LC_LAZY_LOAD_DYLIB`. This lets
the scanner report system framework evidence even when the framework name
appears only in load-command metadata.

Mach-O build metadata is not parsed yet. A future parser can read
`LC_BUILD_VERSION` to report deployment target, SDK, platform, and architecture
details that do not exist as normal strings.

Codesign entitlements and provisioning metadata are not parsed yet. A signed
artifact can contain push, app group, iCloud, associated-domain, or
debug-entitlement state without any matching binary evidence token.
