import 'dart:io';

import 'package:path/path.dart' as p;

import 'ios_evidence.dart';
import 'model.dart';
import 'plist.dart';
import 'privacy_manifest_rules.dart';
import 'rules.dart';

class IosArtifactScanner {
  Future<ScanResult> scan(String artifactPath) async {
    final artifact = _resolveArtifact(artifactPath);
    final findings = <LintFinding>[];
    final infoPlistPath = p.join(artifact.appPath, 'Info.plist');
    Map<String, Object?> infoPlist = {};
    var parsedInfoPlist = false;

    if (!File(infoPlistPath).existsSync()) {
      findings.add(
        buildFinding(
          'ios.info_plist.missing',
          message: 'The app bundle does not contain Info.plist.',
          path: infoPlistPath,
        ),
      );
    } else {
      try {
        infoPlist = parsePlistFile(infoPlistPath);
        parsedInfoPlist = true;
      } on PlistParseException catch (error) {
        findings.add(
          buildFinding(
            'ios.info_plist.invalid',
            message:
                'Info.plist cannot be parsed as a plist: ${error.message}.',
            path: infoPlistPath,
          ),
        );
      }
    }

    findings
      ..addAll(_bundleInfo(infoPlist, artifact))
      ..addAll(
        parsedInfoPlist
            ? _deterministicPlistRules(infoPlist, infoPlistPath)
            : const [],
      )
      ..addAll(_nestedBundleRules(artifact.appPath))
      ..addAll(_privacyManifestRules(artifact.appPath))
      ..addAll(
        _binaryEvidenceRules(
          artifact.appPath,
          infoPlist,
          infoPlistPath: infoPlistPath,
          canCheckMissingPermissions: parsedInfoPlist,
          excludeNestedAppExtensions: true,
        ),
      )
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
  void addInfo(String ruleId, String message) {
    findings.add(buildFinding(ruleId, message: message));
  }

  final bundleId = plist['CFBundleIdentifier'];
  if (bundleId is String && bundleId.trim().isNotEmpty) {
    addInfo('ios.bundle.identifier', bundleId);
  }

  final version = plist['CFBundleShortVersionString'];
  final build = plist['CFBundleVersion'];
  if (version is String || build is String) {
    addInfo(
      'ios.bundle.version',
      '${version ?? 'unknown'} (${build ?? 'unknown'})',
    );
  }

  addInfo('ios.artifact.type', artifact.displayType);
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
      buildFinding(
        'ios.export_compliance.missing',
        message: 'Info.plist is missing ITSAppUsesNonExemptEncryption.',
        path: infoPlistPath,
      ),
    );
  }

  if (plist['UILaunchStoryboardName'] == null &&
      plist['UILaunchScreen'] == null) {
    findings.add(
      buildFinding(
        'ios.launch_screen.missing',
        message:
            'Info.plist is missing UILaunchStoryboardName or UILaunchScreen.',
        path: infoPlistPath,
      ),
    );
  }

  final orientations = plist['UISupportedInterfaceOrientations'];
  if (orientations is! List || orientations.isEmpty) {
    findings.add(
      buildFinding(
        'ios.orientations.missing',
        message:
            'Info.plist does not declare UISupportedInterfaceOrientations.',
        path: infoPlistPath,
      ),
    );
  }

  if (plist['NSLocationAlwaysAndWhenInUseUsageDescription'] is String) {
    final modes = plist['UIBackgroundModes'];
    final hasBackgroundLocation = modes is List && modes.contains('location');
    if (!hasBackgroundLocation) {
      findings.add(
        buildFinding(
          'ios.location.always_without_background_mode',
          message:
              'Always location is declared but UIBackgroundModes does not include location.',
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
        buildFinding(
          entry.value.$1,
          message: '$entry.key is empty or still looks like placeholder text.',
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
    buildFinding(
      'ios.ats.arbitrary_loads',
      message: 'NSAllowsArbitraryLoads is enabled in the release artifact.',
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
        buildFinding(
          'ios.info_plist.missing',
          message: 'The nested bundle does not contain Info.plist.',
          path: infoPlistPath,
        ),
      );
      continue;
    }

    try {
      final plist = parsePlistFile(infoPlistPath);
      findings
        ..add(
          buildFinding(
            'ios.bundle.nested',
            message: p.relative(bundle.path, from: appPath),
            path: bundle.path,
          ),
        )
        ..addAll(_permissionPurposeStringRules(plist, infoPlistPath))
        ..addAll(_atsRules(plist, infoPlistPath))
        ..addAll(
          _binaryEvidenceRules(
            bundle.path,
            plist,
            infoPlistPath: infoPlistPath,
            canCheckMissingPermissions: true,
          ),
        );
    } on PlistParseException catch (error) {
      findings.add(
        buildFinding(
          'ios.info_plist.invalid',
          message:
              'Nested Info.plist cannot be parsed as a plist: ${error.message}.',
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
          buildFinding(
            'ios.privacy_manifest.invalid_accessed_api_types',
            message: 'NSPrivacyAccessedAPITypes must be an array.',
            path: manifest.path,
          ),
        );
        continue;
      }

      for (final apiType in apiTypes) {
        if (apiType is! Map) {
          findings.add(
            buildFinding(
              'ios.privacy_manifest.invalid_accessed_api_types',
              message:
                  'Every NSPrivacyAccessedAPITypes entry must be a dictionary.',
              path: manifest.path,
            ),
          );
          continue;
        }

        final category = apiType['NSPrivacyAccessedAPIType'];
        if (category is! String || category.trim().isEmpty) {
          findings.add(
            buildFinding(
              'ios.privacy_manifest.missing_api_type',
              message:
                  'A privacy manifest accessed API entry is missing NSPrivacyAccessedAPIType.',
              path: manifest.path,
            ),
          );
        }

        if (!_hasReasonCodes(apiType['NSPrivacyAccessedAPITypeReasons'])) {
          findings.add(
            buildFinding(
              'ios.privacy_manifest.empty_reasons',
              message:
                  '${category is String ? category : 'A required reason API category'} has no reason codes.',
              path: manifest.path,
              evidence: category is String ? [category] : const [],
            ),
          );
        }

        if (category is String) {
          findings.addAll(
            _invalidRequiredReasonRules(
              category,
              apiType['NSPrivacyAccessedAPITypeReasons'],
              manifest.path,
            ),
          );
        }
      }
    } on PlistParseException catch (error) {
      findings.add(
        buildFinding(
          'ios.privacy_manifest.invalid',
          message:
              'PrivacyInfo.xcprivacy exists but cannot be parsed as a plist: ${error.message}.',
          path: manifest.path,
        ),
      );
    }
  }
  return findings;
}

List<LintFinding> _invalidRequiredReasonRules(
  String category,
  Object? reasons,
  String manifestPath,
) {
  if (reasons is! List) return const [];
  final allowedReasons = requiredReasonCodesByCategory[category];
  if (allowedReasons == null) return const [];

  final invalidReasons = reasons
      .whereType<String>()
      .where((reason) => reason.trim().isNotEmpty)
      .where((reason) => !allowedReasons.contains(reason))
      .toList();
  if (invalidReasons.isEmpty) return const [];

  return [
    buildFinding(
      'ios.privacy_manifest.invalid_reason',
      message:
          '${invalidReasons.join(' / ')} is not valid for $category. Allowed reason codes: ${allowedReasons.join(', ')}.',
      path: manifestPath,
      evidence: [category, ...invalidReasons],
    ),
  ];
}

List<LintFinding> _binaryEvidenceRules(
  String appPath,
  Map<String, Object?> plist, {
  required String infoPlistPath,
  required bool canCheckMissingPermissions,
  bool excludeNestedAppExtensions = false,
}) {
  final evidence = const IosEvidenceExtractor(
    tokens: _evidenceTokens,
  ).collect(appPath, excludeNestedAppExtensions: excludeNestedAppExtensions);
  final declaredPrivacyCategories = _declaredPrivacyCategories(
    appPath,
    excludeNestedAppExtensions: excludeNestedAppExtensions,
  );
  final findings = <LintFinding>[];

  findings.addAll(_machoSimulatorSliceWarnings(evidence));
  findings.addAll(_machoArchitectureInfo(evidence));
  findings.addAll(_machoBuildVersionInfo(evidence));
  findings.addAll(_machoMetadataInfo(evidence));

  void warnMissingPermission({
    required String ruleId,
    required List<String> plistKeys,
    required List<String> tokens,
  }) {
    final matched = evidence.matched(tokens);
    if (matched.isEmpty || plistKeys.any((key) => plist[key] is String)) {
      return;
    }
    findings.add(
      buildFinding(
        ruleId,
        message:
            '${matched.join(' / ')} detected, but ${plistKeys.join(' or ')} is missing.',
        path: infoPlistPath,
        evidence: matched,
        evidenceSources: evidence.sourcesFor(matched),
      ),
    );
  }

  if (canCheckMissingPermissions) {
    warnMissingPermission(
      ruleId: 'ios.permission.contacts.missing',
      plistKeys: ['NSContactsUsageDescription'],
      tokens: [
        'Contacts.framework',
        'CNContactStore',
        'CNContactPickerViewController',
      ],
    );
    warnMissingPermission(
      ruleId: 'ios.permission.camera.missing',
      plistKeys: ['NSCameraUsageDescription'],
      tokens: [
        'AVCaptureSession',
        'AVCaptureDevice',
        'DataScannerViewController',
      ],
    );
    warnMissingPermission(
      ruleId: 'ios.permission.microphone.missing',
      plistKeys: ['NSMicrophoneUsageDescription'],
      tokens: ['AVAudioRecorder', 'AVAudioEngine', 'SFSpeechRecognizer'],
    );
    warnMissingPermission(
      ruleId: 'ios.permission.location.missing',
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
      plistKeys: ['NSBluetoothAlwaysUsageDescription'],
      tokens: [
        'CoreBluetooth.framework',
        'CBCentralManager',
        'CBPeripheralManager',
      ],
    );
    warnMissingPermission(
      ruleId: 'ios.permission.face_id.missing',
      plistKeys: ['NSFaceIDUsageDescription'],
      tokens: [
        'LocalAuthentication.framework',
        'LAContext',
        'deviceOwnerAuthenticationWithBiometrics',
      ],
    );
  }

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
      buildFinding(
        'ios.notification.evidence',
        message:
            '${notificationEvidence.join(' / ')} detected; notification authorization and push entitlements are runtime or signed-artifact concerns.',
        evidence: notificationEvidence,
        evidenceSources: evidence.sourcesFor(notificationEvidence),
      ),
    );
  }

  for (final rule in _requiredReasonApiRules) {
    final matched = _matchedEvidence(evidence, rule.tokens);
    if (matched.isEmpty || declaredPrivacyCategories.contains(rule.category)) {
      continue;
    }
    findings.add(
      buildFinding(
        rule.ruleId,
        message:
            '${matched.join(' / ')} detected, but ${rule.category} was not declared in PrivacyInfo.xcprivacy.',
        evidence: matched,
        evidenceSources: evidence.sourcesFor(matched),
      ),
    );
  }

  final uiWebViewEvidence = _matchedEvidence(evidence, ['UIWebView']);
  if (uiWebViewEvidence.isNotEmpty) {
    findings.add(
      buildFinding(
        'ios.private_api.uiwebview',
        message: 'UIWebView traces were detected in the release artifact.',
        evidence: uiWebViewEvidence,
        evidenceSources: evidence.sourcesFor(uiWebViewEvidence),
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
      buildFinding(
        'ios.private_api.selector',
        message:
            '${privateSelectorEvidence.join(' / ')} looks like private Apple API usage.',
        evidence: privateSelectorEvidence,
        evidenceSources: evidence.sourcesFor(privateSelectorEvidence),
      ),
    );
  }

  final privateFrameworkEvidence = _privateFrameworkEvidence(evidence);
  if (privateFrameworkEvidence.isNotEmpty) {
    findings.add(
      buildFinding(
        'ios.private_api.framework',
        message:
            '${privateFrameworkEvidence.join(' / ')} links a private Apple framework.',
        evidence: privateFrameworkEvidence,
        evidenceSources: evidence.sourcesFor(privateFrameworkEvidence),
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
      buildFinding(
        'ios.dynamic_code_execution.evidence',
        message:
            '${dynamicCodeEvidence.join(' / ')} detected in the release artifact.',
        evidence: dynamicCodeEvidence,
        evidenceSources: evidence.sourcesFor(dynamicCodeEvidence),
      ),
    );
  }

  return findings;
}

LintFinding _signingInfo(IosArtifact artifact) {
  if (artifact.type == ArtifactType.unsignedApp) {
    return buildFinding(
      'ios.signing.unavailable',
      message: 'unavailable (unsigned artifact)',
    );
  }

  return buildFinding(
    'ios.signing.present',
    message: 'signed artifact detected',
  );
}

Set<String> _declaredPrivacyCategories(
  String appPath, {
  bool excludeNestedAppExtensions = false,
}) {
  final categories = <String>{};
  for (final manifest in _findFiles(
    appPath,
    'PrivacyInfo.xcprivacy',
    excludeNestedAppExtensions: excludeNestedAppExtensions,
  )) {
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

List<String> _privateFrameworkEvidence(EvidenceReport evidence) {
  return evidence.tokens
      .where((token) => token.contains('/PrivateFrameworks/'))
      .toList()
    ..sort();
}

List<LintFinding> _machoArchitectureInfo(EvidenceReport evidence) {
  return evidence.architectures.map((architectureEvidence) {
    final names =
        architectureEvidence.architectures
            .map((architecture) => architecture.name)
            .toSet()
            .toList()
          ..sort();
    return buildFinding(
      'ios.macho.architecture',
      message: names.join(', '),
      path: architectureEvidence.sourcePath,
      evidence: names,
    );
  }).toList();
}

List<LintFinding> _machoBuildVersionInfo(EvidenceReport evidence) {
  return evidence.buildVersions
      .map(
        (buildVersionEvidence) => buildFinding(
          'ios.macho.build_version',
          message:
              '${buildVersionEvidence.buildVersion.platformName} minimum OS ${buildVersionEvidence.buildVersion.minimumOsVersion}, SDK ${buildVersionEvidence.buildVersion.sdkVersion}.',
          path: buildVersionEvidence.sourcePath,
          evidence: [
            buildVersionEvidence.buildVersion.platformName,
            buildVersionEvidence.buildVersion.minimumOsVersion,
            buildVersionEvidence.buildVersion.sdkVersion,
          ],
        ),
      )
      .toList();
}

List<LintFinding> _machoMetadataInfo(EvidenceReport evidence) {
  return evidence.machOMetadata.map((metadata) {
    final ruleId = switch (metadata.kind) {
      MachOMetadataKind.rpath => 'ios.macho.rpath',
      MachOMetadataKind.dylibId => 'ios.macho.dylib_id',
      MachOMetadataKind.uuid => 'ios.macho.uuid',
      MachOMetadataKind.sourceVersion => 'ios.macho.source_version',
      MachOMetadataKind.codeSignature => 'ios.macho.code_signature',
      MachOMetadataKind.encryptionInfo => 'ios.macho.encryption_info',
      MachOMetadataKind.entryPoint => 'ios.macho.entry_point',
      MachOMetadataKind.chainedFixups => 'ios.macho.chained_fixups',
      MachOMetadataKind.functionStarts => 'ios.macho.function_starts',
      MachOMetadataKind.dataInCode => 'ios.macho.data_in_code',
    };
    return buildFinding(
      ruleId,
      message: metadata.value,
      path: metadata.sourcePath,
      evidence: [metadata.value],
    );
  }).toList();
}

List<LintFinding> _machoSimulatorSliceWarnings(EvidenceReport evidence) {
  final detectedByPath = <String, Set<String>>{};

  for (final architectureEvidence in evidence.architectures) {
    final simulatorArchitectures = architectureEvidence.architectures
        .map((architecture) => architecture.name)
        .where(_isSimulatorArchitecture)
        .toList();
    if (simulatorArchitectures.isEmpty) continue;

    detectedByPath
        .putIfAbsent(architectureEvidence.sourcePath, () => <String>{})
        .addAll(simulatorArchitectures);
  }

  for (final buildVersionEvidence in evidence.buildVersions) {
    final platformName = buildVersionEvidence.buildVersion.platformName;
    if (!platformName.contains('Simulator')) continue;

    detectedByPath
        .putIfAbsent(buildVersionEvidence.sourcePath, () => <String>{})
        .add(platformName);
  }

  return detectedByPath.entries.map((entry) {
    final evidence = entry.value.toList()..sort();
    return buildFinding(
      'ios.macho.simulator_slice',
      message: '${evidence.join(' / ')} detected in a release artifact binary.',
      path: entry.key,
      evidence: evidence,
    );
  }).toList();
}

bool _isSimulatorArchitecture(String architecture) {
  return architecture == 'x86_64' || architecture == 'i386';
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

List<File> _findFiles(
  String root,
  String basename, {
  bool excludeNestedAppExtensions = false,
}) {
  return Directory(root)
      .listSync(recursive: true, followLinks: false)
      .whereType<File>()
      .where(
        (file) =>
            !excludeNestedAppExtensions ||
            !_isInsideNestedAppExtension(root, file.path),
      )
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

bool _isInsideNestedAppExtension(String root, String path) {
  final relative = p.relative(path, from: root);
  if (relative == '.') return false;

  for (final part in p.split(relative)) {
    if (part.endsWith('.appex')) return true;
  }
  return false;
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
