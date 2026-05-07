import 'dart:io';

import 'package:path/path.dart' as p;

import 'ios_evidence.dart';
import 'model.dart';
import 'plist.dart';
import 'rules.dart';

class IosArtifactScanner {
  Future<ScanResult> scan(String artifactPath) async {
    final artifact = _resolveArtifact(artifactPath);
    final findings = <LintFinding>[];
    final infoPlistPath = p.join(artifact.appPath, 'Info.plist');
    Map<String, Object?> infoPlist = {};

    if (!File(infoPlistPath).existsSync()) {
      findings.add(
        LintFinding(
          level: FindingLevel.failed,
          ruleId: 'ios.info_plist.missing',
          title: 'Missing Info.plist',
          message: 'The app bundle does not contain Info.plist.',
          fix: 'Build a valid iOS app bundle before scanning.',
          path: infoPlistPath,
        ),
      );
    } else {
      try {
        infoPlist = parsePlistFile(infoPlistPath);
      } on PlistParseException catch (error) {
        findings.add(
          LintFinding(
            level: FindingLevel.failed,
            ruleId: 'ios.info_plist.invalid',
            title: 'Invalid Info.plist',
            message:
                'Info.plist cannot be parsed as a plist: ${error.message}.',
            fix: 'Fix or regenerate Info.plist.',
            path: infoPlistPath,
          ),
        );
      }
    }

    findings
      ..addAll(_bundleInfo(infoPlist, artifact))
      ..addAll(_deterministicPlistRules(infoPlist, infoPlistPath))
      ..addAll(_nestedBundleRules(artifact.appPath))
      ..addAll(_privacyManifestRules(artifact.appPath))
      ..addAll(_binaryEvidenceRules(artifact.appPath, infoPlist))
      ..add(_signingInfo(artifact));

    assert(_findingsAreRegistered(findings));
    return ScanResult(artifact: artifact, findings: findings);
  }

  IosArtifact _resolveArtifact(String artifactPath) {
    final normalized = p.normalize(p.absolute(artifactPath));
    final type = FileSystemEntity.typeSync(normalized);

    if (type == FileSystemEntityType.directory && normalized.endsWith('.app')) {
      final signed = Directory(
        p.join(normalized, '_CodeSignature'),
      ).existsSync();
      return IosArtifact(
        path: normalized,
        appPath: normalized,
        type: signed ? ArtifactType.signedApp : ArtifactType.unsignedApp,
      );
    }

    if (type == FileSystemEntityType.directory &&
        normalized.endsWith('.xcarchive')) {
      final productsDir = Directory(
        p.join(normalized, 'Products', 'Applications'),
      );
      final apps = productsDir.existsSync()
          ? productsDir
                .listSync()
                .whereType<Directory>()
                .where((directory) => directory.path.endsWith('.app'))
                .toList()
          : <Directory>[];
      if (apps.length != 1) {
        throw ArtifactScanException(
          'Expected exactly one .app in ${productsDir.path}, found ${apps.length}.',
        );
      }
      return IosArtifact(
        path: normalized,
        appPath: p.normalize(p.absolute(apps.single.path)),
        type: ArtifactType.xcarchive,
      );
    }

    throw ArtifactScanException('Unsupported iOS artifact: $artifactPath');
  }
}

class ArtifactScanException implements Exception {
  const ArtifactScanException(this.message);

  final String message;

  @override
  String toString() => message;
}

List<LintFinding> _bundleInfo(
  Map<String, Object?> plist,
  IosArtifact artifact,
) {
  final findings = <LintFinding>[];
  void addInfo(String ruleId, String title, String message) {
    findings.add(
      LintFinding(
        level: FindingLevel.info,
        ruleId: ruleId,
        title: title,
        message: message,
      ),
    );
  }

  final bundleId = plist['CFBundleIdentifier'];
  if (bundleId is String && bundleId.trim().isNotEmpty) {
    addInfo('ios.bundle.identifier', 'Bundle ID', bundleId);
  }

  final version = plist['CFBundleShortVersionString'];
  final build = plist['CFBundleVersion'];
  if (version is String || build is String) {
    addInfo(
      'ios.bundle.version',
      'Version',
      '${version ?? 'unknown'} (${build ?? 'unknown'})',
    );
  }

  addInfo('ios.artifact.type', 'Artifact type', artifact.displayType);
  return findings;
}

List<LintFinding> _deterministicPlistRules(
  Map<String, Object?> plist,
  String infoPlistPath,
) {
  final findings = <LintFinding>[
    ..._permissionPurposeStringRules(plist, infoPlistPath),
    ..._atsRules(plist, infoPlistPath),
  ];

  if (plist['ITSAppUsesNonExemptEncryption'] == null) {
    findings.add(
      LintFinding(
        level: FindingLevel.failed,
        ruleId: 'ios.export_compliance.missing',
        title: 'Missing export compliance flag',
        message: 'Info.plist is missing ITSAppUsesNonExemptEncryption.',
        fix:
            'Add ITSAppUsesNonExemptEncryption with the correct value for your app.',
        path: infoPlistPath,
      ),
    );
  }

  if (plist['UILaunchStoryboardName'] == null &&
      plist['UILaunchScreen'] == null) {
    findings.add(
      LintFinding(
        level: FindingLevel.failed,
        ruleId: 'ios.launch_screen.missing',
        title: 'Missing launch screen',
        message:
            'Info.plist is missing UILaunchStoryboardName or UILaunchScreen.',
        fix: 'Configure a launch storyboard or launch screen.',
        path: infoPlistPath,
      ),
    );
  }

  final orientations = plist['UISupportedInterfaceOrientations'];
  if (orientations is! List || orientations.isEmpty) {
    findings.add(
      LintFinding(
        level: FindingLevel.failed,
        ruleId: 'ios.orientations.missing',
        title: 'Missing supported orientations',
        message:
            'Info.plist does not declare UISupportedInterfaceOrientations.',
        fix: 'Declare at least one supported interface orientation.',
        path: infoPlistPath,
      ),
    );
  }

  if (plist['NSLocationAlwaysAndWhenInUseUsageDescription'] is String) {
    final modes = plist['UIBackgroundModes'];
    final hasBackgroundLocation = modes is List && modes.contains('location');
    if (!hasBackgroundLocation) {
      findings.add(
        LintFinding(
          level: FindingLevel.failed,
          ruleId: 'ios.location.always_without_background_mode',
          title: 'Always location lacks background mode',
          message:
              'Always location is declared but UIBackgroundModes does not include location.',
          fix:
              'Add the location background mode only if the app truly needs always-on location.',
          path: infoPlistPath,
        ),
      );
    }
  }

  return findings;
}

List<LintFinding> _permissionPurposeStringRules(
  Map<String, Object?> plist,
  String infoPlistPath,
) {
  final findings = <LintFinding>[];
  const permissionKeys = {
    'NSCameraUsageDescription': (
      'ios.permission.camera.empty',
      'Camera purpose string',
    ),
    'NSMicrophoneUsageDescription': (
      'ios.permission.microphone.empty',
      'Microphone purpose string',
    ),
    'NSPhotoLibraryUsageDescription': (
      'ios.permission.photos.empty',
      'Photo library purpose string',
    ),
    'NSContactsUsageDescription': (
      'ios.permission.contacts.empty',
      'Contacts purpose string',
    ),
    'NSBluetoothAlwaysUsageDescription': (
      'ios.permission.bluetooth.empty',
      'Bluetooth purpose string',
    ),
    'NSFaceIDUsageDescription': (
      'ios.permission.face_id.empty',
      'Face ID purpose string',
    ),
  };

  for (final entry in permissionKeys.entries) {
    final value = plist[entry.key];
    if (value is String && _isPlaceholder(value)) {
      findings.add(
        LintFinding(
          level: FindingLevel.failed,
          ruleId: entry.value.$1,
          title: 'Invalid ${entry.value.$2}',
          message: '$entry.key is empty or still looks like placeholder text.',
          fix: 'Replace $entry.key with a specific user-facing explanation.',
          path: infoPlistPath,
        ),
      );
    }
  }

  return findings;
}

List<LintFinding> _atsRules(Map<String, Object?> plist, String infoPlistPath) {
  final ats = plist['NSAppTransportSecurity'];
  if (ats is! Map || ats['NSAllowsArbitraryLoads'] != true) return const [];

  return [
    LintFinding(
      level: FindingLevel.failed,
      ruleId: 'ios.ats.arbitrary_loads',
      title: 'ATS allows arbitrary loads',
      message: 'NSAllowsArbitraryLoads is enabled in the release artifact.',
      fix:
          'Remove the global ATS exception or replace it with narrow exception domains.',
      path: infoPlistPath,
    ),
  ];
}

List<LintFinding> _nestedBundleRules(String appPath) {
  final findings = <LintFinding>[];
  for (final bundle in _findNestedAppBundles(appPath)) {
    final infoPlistPath = p.join(bundle.path, 'Info.plist');
    if (!File(infoPlistPath).existsSync()) {
      findings.add(
        LintFinding(
          level: FindingLevel.failed,
          ruleId: 'ios.info_plist.missing',
          title: 'Missing Info.plist',
          message: 'The nested bundle does not contain Info.plist.',
          fix: 'Build a valid iOS app extension before scanning.',
          path: infoPlistPath,
        ),
      );
      continue;
    }

    try {
      final plist = parsePlistFile(infoPlistPath);
      findings
        ..add(
          LintFinding(
            level: FindingLevel.info,
            ruleId: 'ios.bundle.nested',
            title: 'Nested bundle',
            message: p.relative(bundle.path, from: appPath),
            path: bundle.path,
          ),
        )
        ..addAll(_permissionPurposeStringRules(plist, infoPlistPath))
        ..addAll(_atsRules(plist, infoPlistPath));
    } on PlistParseException catch (error) {
      findings.add(
        LintFinding(
          level: FindingLevel.failed,
          ruleId: 'ios.info_plist.invalid',
          title: 'Invalid Info.plist',
          message:
              'Nested Info.plist cannot be parsed as a plist: ${error.message}.',
          fix: 'Fix or regenerate Info.plist.',
          path: infoPlistPath,
        ),
      );
    }
  }
  return findings;
}

List<LintFinding> _privacyManifestRules(String appPath) {
  final findings = <LintFinding>[];
  for (final manifest in _findFiles(appPath, 'PrivacyInfo.xcprivacy')) {
    try {
      final plist = parsePlistFile(manifest.path);
      final apiTypes = plist['NSPrivacyAccessedAPITypes'];
      if (apiTypes == null) continue;
      if (apiTypes is! List) {
        findings.add(
          LintFinding(
            level: FindingLevel.failed,
            ruleId: 'ios.privacy_manifest.invalid_accessed_api_types',
            title: 'Invalid accessed API declaration',
            message: 'NSPrivacyAccessedAPITypes must be an array.',
            fix: 'Use an array of accessed API type dictionaries.',
            path: manifest.path,
          ),
        );
        continue;
      }

      for (final apiType in apiTypes) {
        if (apiType is! Map) {
          findings.add(
            LintFinding(
              level: FindingLevel.failed,
              ruleId: 'ios.privacy_manifest.invalid_accessed_api_types',
              title: 'Invalid accessed API declaration',
              message:
                  'Every NSPrivacyAccessedAPITypes entry must be a dictionary.',
              fix: 'Replace invalid entries with accessed API dictionaries.',
              path: manifest.path,
            ),
          );
          continue;
        }

        final category = apiType['NSPrivacyAccessedAPIType'];
        if (category is! String || category.trim().isEmpty) {
          findings.add(
            LintFinding(
              level: FindingLevel.failed,
              ruleId: 'ios.privacy_manifest.missing_api_type',
              title: 'Missing accessed API type',
              message:
                  'A privacy manifest accessed API entry is missing NSPrivacyAccessedAPIType.',
              fix: 'Declare the required reason API category.',
              path: manifest.path,
            ),
          );
        }

        if (!_hasReasonCodes(apiType['NSPrivacyAccessedAPITypeReasons'])) {
          findings.add(
            LintFinding(
              level: FindingLevel.failed,
              ruleId: 'ios.privacy_manifest.empty_reasons',
              title: 'Missing required reason codes',
              message:
                  '${category is String ? category : 'A required reason API category'} has no reason codes.',
              fix: 'Add at least one NSPrivacyAccessedAPITypeReasons code.',
              path: manifest.path,
              evidence: category is String ? [category] : const [],
            ),
          );
        }
      }
    } on PlistParseException catch (error) {
      findings.add(
        LintFinding(
          level: FindingLevel.failed,
          ruleId: 'ios.privacy_manifest.invalid',
          title: 'Invalid privacy manifest',
          message:
              'PrivacyInfo.xcprivacy exists but cannot be parsed as a plist: ${error.message}.',
          fix: 'Replace it with a valid App Privacy manifest.',
          path: manifest.path,
        ),
      );
    }
  }
  return findings;
}

List<LintFinding> _binaryEvidenceRules(
  String appPath,
  Map<String, Object?> plist,
) {
  final evidence = const IosEvidenceExtractor(
    tokens: _evidenceTokens,
  ).collect(appPath);
  final declaredPrivacyCategories = _declaredPrivacyCategories(appPath);
  final findings = <LintFinding>[];

  void warnMissingPermission({
    required String ruleId,
    required String title,
    required List<String> plistKeys,
    required List<String> tokens,
  }) {
    final matched = evidence.matched(tokens);
    if (matched.isEmpty || plistKeys.any((key) => plist[key] is String)) {
      return;
    }
    findings.add(
      LintFinding(
        level: FindingLevel.warned,
        ruleId: ruleId,
        title: title,
        message:
            '${matched.join(' / ')} detected, but ${plistKeys.join(' or ')} is missing.',
        fix:
            'Add the matching usage description if this capability is reachable in the release app.',
        evidence: matched,
      ),
    );
  }

  warnMissingPermission(
    ruleId: 'ios.permission.contacts.missing',
    title: 'Contacts API evidence found',
    plistKeys: ['NSContactsUsageDescription'],
    tokens: [
      'Contacts.framework',
      'CNContactStore',
      'CNContactPickerViewController',
    ],
  );
  warnMissingPermission(
    ruleId: 'ios.permission.camera.missing',
    title: 'Camera API evidence found',
    plistKeys: ['NSCameraUsageDescription'],
    tokens: [
      'AVCaptureSession',
      'AVCaptureDevice',
      'DataScannerViewController',
    ],
  );
  warnMissingPermission(
    ruleId: 'ios.permission.microphone.missing',
    title: 'Microphone API evidence found',
    plistKeys: ['NSMicrophoneUsageDescription'],
    tokens: ['AVAudioRecorder', 'AVAudioEngine', 'SFSpeechRecognizer'],
  );
  warnMissingPermission(
    ruleId: 'ios.permission.location.missing',
    title: 'Location API evidence found',
    plistKeys: [
      'NSLocationWhenInUseUsageDescription',
      'NSLocationAlwaysAndWhenInUseUsageDescription',
      'NSLocationAlwaysUsageDescription',
    ],
    tokens: [
      'CoreLocation.framework',
      'CLLocationManager',
      'requestWhenInUseAuthorization',
      'requestAlwaysAuthorization',
    ],
  );
  warnMissingPermission(
    ruleId: 'ios.permission.photos.missing',
    title: 'Photo library API evidence found',
    plistKeys: [
      'NSPhotoLibraryUsageDescription',
      'NSPhotoLibraryAddUsageDescription',
    ],
    tokens: [
      'Photos.framework',
      'PhotosUI.framework',
      'PHPhotoLibrary',
      'PHPickerViewController',
      'UIImagePickerController',
    ],
  );
  warnMissingPermission(
    ruleId: 'ios.permission.bluetooth.missing',
    title: 'Bluetooth API evidence found',
    plistKeys: ['NSBluetoothAlwaysUsageDescription'],
    tokens: [
      'CoreBluetooth.framework',
      'CBCentralManager',
      'CBPeripheralManager',
    ],
  );
  warnMissingPermission(
    ruleId: 'ios.permission.face_id.missing',
    title: 'Face ID API evidence found',
    plistKeys: ['NSFaceIDUsageDescription'],
    tokens: [
      'LocalAuthentication.framework',
      'LAContext',
      'deviceOwnerAuthenticationWithBiometrics',
    ],
  );

  final notificationEvidence = _matchedEvidence(evidence, [
    'UserNotifications.framework',
    'UNUserNotificationCenter',
    'requestAuthorization',
    'FirebaseMessaging',
    'OneSignal',
    'Braze',
    'Airship',
  ]);
  if (notificationEvidence.isNotEmpty) {
    findings.add(
      LintFinding(
        level: FindingLevel.warned,
        ruleId: 'ios.notification.evidence',
        title: 'Notification evidence found',
        message:
            '${notificationEvidence.join(' / ')} detected; notification authorization and push entitlements are runtime or signed-artifact concerns.',
        fix:
            'Verify the app requests notification authorization intentionally and check push entitlements after signing.',
        evidence: notificationEvidence,
      ),
    );
  }

  for (final rule in _requiredReasonApiRules) {
    final matched = _matchedEvidence(evidence, rule.tokens);
    if (matched.isEmpty || declaredPrivacyCategories.contains(rule.category)) {
      continue;
    }
    findings.add(
      LintFinding(
        level: FindingLevel.warned,
        ruleId: rule.ruleId,
        title: rule.title,
        message:
            '${matched.join(' / ')} detected, but ${rule.category} was not declared in PrivacyInfo.xcprivacy.',
        fix:
            'Declare ${rule.category} with a valid required reason if this API is reachable in the release app.',
        evidence: matched,
      ),
    );
  }

  final uiWebViewEvidence = _matchedEvidence(evidence, ['UIWebView']);
  if (uiWebViewEvidence.isNotEmpty) {
    findings.add(
      LintFinding(
        level: FindingLevel.warned,
        ruleId: 'ios.private_api.uiwebview',
        title: 'UIWebView evidence found',
        message: 'UIWebView traces were detected in the release artifact.',
        fix: 'Remove old SDKs or code paths that still reference UIWebView.',
        evidence: uiWebViewEvidence,
      ),
    );
  }

  final privateSelectorEvidence = _matchedEvidence(evidence, [
    '_UIApplicationOpenSettingsURLString',
    '_setAlwaysRunsAtForegroundPriority:',
    '_terminateWithStatus:',
  ]);
  if (privateSelectorEvidence.isNotEmpty) {
    findings.add(
      LintFinding(
        level: FindingLevel.warned,
        ruleId: 'ios.private_api.selector',
        title: 'Private selector evidence found',
        message:
            '${privateSelectorEvidence.join(' / ')} looks like private Apple API usage.',
        fix: 'Remove private API references from app code and bundled SDKs.',
        evidence: privateSelectorEvidence,
      ),
    );
  }

  final dynamicCodeEvidence = _matchedEvidence(evidence, [
    'dlopen',
    'dlsym',
    'JSContext',
    'evaluateScript',
  ]);
  if (dynamicCodeEvidence.isNotEmpty) {
    findings.add(
      LintFinding(
        level: FindingLevel.warned,
        ruleId: 'ios.dynamic_code_execution.evidence',
        title: 'Dynamic code execution evidence found',
        message:
            '${dynamicCodeEvidence.join(' / ')} detected in the release artifact.',
        fix:
            'Verify this is limited to allowed SDK behavior and does not download or execute new app code.',
        evidence: dynamicCodeEvidence,
      ),
    );
  }

  return findings;
}

LintFinding _signingInfo(IosArtifact artifact) {
  if (artifact.type == ArtifactType.unsignedApp) {
    return const LintFinding(
      level: FindingLevel.info,
      ruleId: 'ios.signing.unavailable',
      title: 'Signing',
      message: 'unavailable (unsigned artifact)',
    );
  }

  return const LintFinding(
    level: FindingLevel.info,
    ruleId: 'ios.signing.present',
    title: 'Signing',
    message: 'signed artifact detected',
  );
}

Set<String> _declaredPrivacyCategories(String appPath) {
  final categories = <String>{};
  for (final manifest in _findFiles(appPath, 'PrivacyInfo.xcprivacy')) {
    try {
      final plist = parsePlistFile(manifest.path);
      final apiTypes = plist['NSPrivacyAccessedAPITypes'];
      if (apiTypes is! List) continue;
      for (final apiType in apiTypes) {
        if (apiType is! Map) continue;
        final category = apiType['NSPrivacyAccessedAPIType'];
        if (category is String && category.trim().isNotEmpty) {
          categories.add(category);
        }
      }
    } catch (_) {
      // Invalid manifests are reported by the deterministic manifest rule.
    }
  }
  return categories;
}

bool _hasReasonCodes(Object? reasons) {
  return reasons is List &&
      reasons.any((reason) => reason is String && reason.trim().isNotEmpty);
}

List<String> _matchedEvidence(EvidenceReport evidence, List<String> tokens) {
  return evidence.matched(tokens);
}

const _evidenceTokens = [
  'CNContactStore',
  'CNContactPickerViewController',
  'AVCaptureSession',
  'AVCaptureDevice',
  'DataScannerViewController',
  'AVAudioRecorder',
  'AVAudioEngine',
  'SFSpeechRecognizer',
  'CLLocationManager',
  'requestWhenInUseAuthorization',
  'requestAlwaysAuthorization',
  'PHPhotoLibrary',
  'PHPickerViewController',
  'UIImagePickerController',
  'CBCentralManager',
  'CBPeripheralManager',
  'LAContext',
  'deviceOwnerAuthenticationWithBiometrics',
  'UNUserNotificationCenter',
  'requestAuthorization',
  'FirebaseMessaging',
  'OneSignal',
  'Braze',
  'Airship',
  'UserDefaults',
  'NSUserDefaults',
  'NSFileModificationDate',
  'NSFileCreationDate',
  'NSURLContentModificationDateKey',
  'contentModificationDateKey',
  'statfs',
  'statvfs',
  'volumeAvailableCapacityKey',
  'NSFileSystemFreeSize',
  'systemUptime',
  'mach_absolute_time',
  'activeInputModes',
  'UIWebView',
  '_UIApplicationOpenSettingsURLString',
  '_setAlwaysRunsAtForegroundPriority:',
  '_terminateWithStatus:',
  'dlopen',
  'dlsym',
  'JSContext',
  'evaluateScript',
];

const _requiredReasonApiRules = [
  (
    ruleId: 'ios.required_reason.user_defaults',
    title: 'UserDefaults Required Reason API evidence found',
    category: 'NSPrivacyAccessedAPICategoryUserDefaults',
    tokens: ['UserDefaults', 'NSUserDefaults'],
  ),
  (
    ruleId: 'ios.required_reason.file_timestamp',
    title: 'File timestamp Required Reason API evidence found',
    category: 'NSPrivacyAccessedAPICategoryFileTimestamp',
    tokens: [
      'NSFileModificationDate',
      'NSFileCreationDate',
      'NSURLContentModificationDateKey',
      'contentModificationDateKey',
    ],
  ),
  (
    ruleId: 'ios.required_reason.disk_space',
    title: 'Disk space Required Reason API evidence found',
    category: 'NSPrivacyAccessedAPICategoryDiskSpace',
    tokens: [
      'statfs',
      'statvfs',
      'volumeAvailableCapacityKey',
      'NSFileSystemFreeSize',
    ],
  ),
  (
    ruleId: 'ios.required_reason.system_boot_time',
    title: 'System boot time Required Reason API evidence found',
    category: 'NSPrivacyAccessedAPICategorySystemBootTime',
    tokens: ['systemUptime', 'mach_absolute_time'],
  ),
  (
    ruleId: 'ios.required_reason.active_keyboards',
    title: 'Active keyboards Required Reason API evidence found',
    category: 'NSPrivacyAccessedAPICategoryActiveKeyboards',
    tokens: ['activeInputModes'],
  ),
];

List<File> _findFiles(String root, String basename) {
  return Directory(root)
      .listSync(recursive: true, followLinks: false)
      .whereType<File>()
      .where((file) => p.basename(file.path) == basename)
      .toList();
}

List<Directory> _findNestedAppBundles(String appPath) {
  return Directory(appPath)
      .listSync(recursive: true, followLinks: false)
      .whereType<Directory>()
      .where((directory) => directory.path.endsWith('.appex'))
      .toList();
}

bool _findingsAreRegistered(List<LintFinding> findings) {
  for (final finding in findings) {
    assert(isKnownRule(finding.ruleId), 'Unregistered rule: ${finding.ruleId}');
  }
  return true;
}

bool _isPlaceholder(String value) {
  final normalized = value.trim().toLowerCase();
  if (normalized.isEmpty) return true;
  return normalized == 'todo' ||
      normalized == 'fixme' ||
      normalized.contains('placeholder') ||
      normalized.contains('description here') ||
      normalized.contains('add description');
}
