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

`ios.macho.simulator_slice` reports simulator architecture or platform metadata in a release artifact binary.

`ios.dynamic_code_execution.evidence` reports dynamic loading or script execution evidence.

## Info

`ios.bundle.identifier` reports the artifact bundle identifier.

`ios.bundle.version` reports the artifact version and build number.

`ios.bundle.nested` reports an app extension bundle found inside the app.

`ios.artifact.type` reports the scanned artifact type.

`ios.macho.build_version` reports platform, minimum OS, and SDK metadata from `LC_BUILD_VERSION`.

`ios.macho.architecture` reports architecture slices found in Mach-O binaries.

`ios.macho.rpath` reports runtime library search paths from `LC_RPATH`.

`ios.macho.dylib_id` reports dynamic library install names from `LC_ID_DYLIB`.

`ios.macho.uuid` reports binary UUIDs from `LC_UUID`.

`ios.macho.source_version` reports source version metadata from `LC_SOURCE_VERSION`.

`ios.macho.code_signature` reports `LC_CODE_SIGNATURE` offset and size metadata.

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

Mach-O architecture inventory is reported from thin and fat/universal headers.
Mach-O build metadata is parsed from `LC_BUILD_VERSION` and legacy
`LC_VERSION_MIN_*` commands to report platform, minimum OS, and SDK version.
The scanner warns when device release artifacts contain simulator architecture
or simulator platform metadata.

Additional diagnostic metadata is parsed from `LC_RPATH`, `LC_ID_DYLIB`,
`LC_UUID`, `LC_SOURCE_VERSION`, and `LC_CODE_SIGNATURE`. `LC_CODE_SIGNATURE`
currently reports only the linkedit offset and size; it does not validate the
signature blob or parse embedded entitlements.

Segment and section names are parsed from `LC_SEGMENT` and `LC_SEGMENT_64` as
structured parser metadata. Section, symbol, selector, class, protocol, and
method names can contribute token evidence with the parsed Mach-O source
attached.
Symbol table metadata and symbol names are parsed from `LC_SYMTAB` when the
symbol and string tables are present in the artifact.
Dynamic symbol table ranges and indirect-symbol table metadata are parsed from
`LC_DYSYMTAB`.
Imported symbol names are parsed from `LC_DYLD_INFO` and `LC_DYLD_INFO_ONLY`
bind, weak-bind, and lazy-bind opcode streams.
Imported symbol names are also parsed from `LC_DYLD_CHAINED_FIXUPS` import
tables for `DYLD_CHAINED_IMPORT`, `DYLD_CHAINED_IMPORT_ADDEND`, and
`DYLD_CHAINED_IMPORT_ADDEND64` formats, with uncompressed and zlib-compressed
symbol string tables.
Exported symbol names are parsed from `LC_DYLD_INFO` and
`LC_DYLD_INFO_ONLY` export trie streams and from `LC_DYLD_EXPORTS_TRIE`.
C-string values are parsed from `__cstring`, `__objc_methname`,
`__objc_classname`, and `__objc_methtype` sections. Swift metadata strings are
parsed from `__swift5_reflstr` and `__swift5_typeref` sections. Swift nominal
type names are resolved from `__swift5_types` relative context descriptors when
the descriptor and name target sections are present in the artifact. Swift
protocol names are resolved from `__swift5_protos` protocol descriptors. Swift
protocol conformance descriptors are resolved from `__swift5_proto` to recover
the conforming type name and protocol name when both target descriptors are
present. Swift field descriptors are resolved from `__swift5_fieldmd` to recover
stored field names and raw owner/type references when the referenced Swift
metadata strings are present.
Objective-C selector references are resolved from `__objc_selrefs` pointers
back to `__objc_methname` strings when section virtual addresses and file
ranges are available.
Objective-C class references are resolved from `__objc_classrefs` and
`__objc_classlist` through `class_t` and `class_ro_t` metadata to class-name
strings when the relevant sections are present.
Objective-C protocol references are resolved from `__objc_protolist`,
`__objc_protorefs`, `class_ro_t.baseProtocols`, and `category_t.protocols`
through `protocol_t` metadata to protocol-name strings when the relevant
sections are present.
Objective-C big and small method lists are resolved from
`class_ro_t.baseMethods` and local relative method-list lists through
`method_list_t` entries back to `__objc_methname` strings when the relevant
Objective-C metadata sections are present.
Objective-C ivar and property lists are resolved from `class_ro_t.ivars`,
`class_ro_t.baseProperties`, `category_t.instanceProperties`, and
`protocol_t.instanceProperties`, including type encodings and property
attributes that reference Objective-C classes.
Objective-C category instance and class method lists are resolved from
`__objc_catlist` and `__objc_nlcatlist` through `category_t` metadata.
For modern arm64 Mach-O binaries, Objective-C metadata pointers encoded as
dyld chained 64-bit offset pointers are normalized back to section virtual
addresses when the target section is present.

Codesign entitlements and provisioning metadata are not parsed yet. A signed
artifact can contain push, app group, iCloud, associated-domain, or
debug-entitlement state without any matching binary evidence token.
