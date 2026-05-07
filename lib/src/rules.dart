import 'model.dart';

enum RuleSource {
  artifact,
  infoPlist,
  privacyManifest,
  binaryEvidence,
  signing,
  baseline,
}

enum RuleConfidence { deterministic, evidence, informational }

class RuleDefinition {
  const RuleDefinition({
    required this.ruleId,
    required this.defaultLevel,
    required this.source,
    required this.title,
    required this.description,
    required this.fix,
  });

  final String ruleId;
  final FindingLevel defaultLevel;
  final RuleSource source;
  final String title;
  final String description;
  final String fix;

  RuleConfidence get confidence => switch (defaultLevel) {
    FindingLevel.failed => RuleConfidence.deterministic,
    FindingLevel.warned => RuleConfidence.evidence,
    FindingLevel.info => RuleConfidence.informational,
  };
}

class FindingBuilder {
  const FindingBuilder(this.registry);

  final Map<String, RuleDefinition> registry;

  LintFinding build(
    String ruleId, {
    required String message,
    String? path,
    List<String> evidence = const [],
    Map<String, List<String>> evidenceSources = const {},
  }) {
    final rule = registry[ruleId];
    if (rule == null) {
      throw StateError('Unknown rule: $ruleId');
    }

    return LintFinding(
      level: rule.defaultLevel,
      ruleId: rule.ruleId,
      title: rule.title,
      message: message,
      fix: rule.defaultLevel == FindingLevel.info ? null : rule.fix,
      path: path,
      evidence: evidence,
      evidenceSources: evidenceSources,
    );
  }
}

const ruleRegistry = <String, RuleDefinition>{
  'baseline.unused': RuleDefinition(
    ruleId: 'baseline.unused',
    defaultLevel: FindingLevel.info,
    source: RuleSource.baseline,
    title: 'Unused baseline entry',
    description: 'A baseline entry did not match any current finding.',
    fix: 'Remove stale baseline entries or update their path.',
  ),
  'ios.info_plist.missing': RuleDefinition(
    ruleId: 'ios.info_plist.missing',
    defaultLevel: FindingLevel.failed,
    source: RuleSource.infoPlist,
    title: 'Missing Info.plist',
    description: 'The bundle does not contain an Info.plist.',
    fix: 'Build a valid iOS bundle before scanning.',
  ),
  'ios.info_plist.invalid': RuleDefinition(
    ruleId: 'ios.info_plist.invalid',
    defaultLevel: FindingLevel.failed,
    source: RuleSource.infoPlist,
    title: 'Invalid Info.plist',
    description: 'The bundle Info.plist cannot be parsed.',
    fix: 'Fix or regenerate the Info.plist.',
  ),
  'ios.bundle.identifier': RuleDefinition(
    ruleId: 'ios.bundle.identifier',
    defaultLevel: FindingLevel.info,
    source: RuleSource.artifact,
    title: 'Bundle ID',
    description: 'Reports the final bundle identifier in the artifact.',
    fix: 'No action required.',
  ),
  'ios.bundle.version': RuleDefinition(
    ruleId: 'ios.bundle.version',
    defaultLevel: FindingLevel.info,
    source: RuleSource.artifact,
    title: 'Version',
    description: 'Reports the final marketing version and build number.',
    fix: 'No action required.',
  ),
  'ios.bundle.nested': RuleDefinition(
    ruleId: 'ios.bundle.nested',
    defaultLevel: FindingLevel.info,
    source: RuleSource.artifact,
    title: 'Nested bundle',
    description: 'Reports an app extension bundle found inside the app.',
    fix: 'No action required.',
  ),
  'ios.artifact.type': RuleDefinition(
    ruleId: 'ios.artifact.type',
    defaultLevel: FindingLevel.info,
    source: RuleSource.artifact,
    title: 'Artifact type',
    description: 'Reports whether the scanner saw an app or archive artifact.',
    fix: 'No action required.',
  ),
  'ios.macho.build_version': RuleDefinition(
    ruleId: 'ios.macho.build_version',
    defaultLevel: FindingLevel.info,
    source: RuleSource.artifact,
    title: 'Mach-O build version',
    description:
        'Reports platform, minimum OS, SDK, and tool metadata from LC_BUILD_VERSION.',
    fix: 'No action required.',
  ),
  'ios.macho.architecture': RuleDefinition(
    ruleId: 'ios.macho.architecture',
    defaultLevel: FindingLevel.info,
    source: RuleSource.artifact,
    title: 'Mach-O architecture',
    description: 'Reports architecture slices found in Mach-O binaries.',
    fix: 'No action required.',
  ),
  'ios.macho.header': RuleDefinition(
    ruleId: 'ios.macho.header',
    defaultLevel: FindingLevel.info,
    source: RuleSource.artifact,
    title: 'Mach-O header',
    description: 'Reports Mach-O file type and header flags.',
    fix: 'No action required.',
  ),
  'ios.macho.rpath': RuleDefinition(
    ruleId: 'ios.macho.rpath',
    defaultLevel: FindingLevel.info,
    source: RuleSource.artifact,
    title: 'Mach-O rpath',
    description: 'Reports runtime library search paths from LC_RPATH.',
    fix: 'No action required.',
  ),
  'ios.macho.dylib_id': RuleDefinition(
    ruleId: 'ios.macho.dylib_id',
    defaultLevel: FindingLevel.info,
    source: RuleSource.artifact,
    title: 'Mach-O dylib id',
    description: 'Reports dynamic library install names from LC_ID_DYLIB.',
    fix: 'No action required.',
  ),
  'ios.macho.uuid': RuleDefinition(
    ruleId: 'ios.macho.uuid',
    defaultLevel: FindingLevel.info,
    source: RuleSource.artifact,
    title: 'Mach-O UUID',
    description: 'Reports binary UUIDs from LC_UUID.',
    fix: 'No action required.',
  ),
  'ios.macho.source_version': RuleDefinition(
    ruleId: 'ios.macho.source_version',
    defaultLevel: FindingLevel.info,
    source: RuleSource.artifact,
    title: 'Mach-O source version',
    description: 'Reports source version metadata from LC_SOURCE_VERSION.',
    fix: 'No action required.',
  ),
  'ios.macho.linker_option': RuleDefinition(
    ruleId: 'ios.macho.linker_option',
    defaultLevel: FindingLevel.info,
    source: RuleSource.artifact,
    title: 'Mach-O linker option',
    description: 'Reports linker option strings from LC_LINKER_OPTION.',
    fix: 'No action required.',
  ),
  'ios.macho.dylinker': RuleDefinition(
    ruleId: 'ios.macho.dylinker',
    defaultLevel: FindingLevel.info,
    source: RuleSource.artifact,
    title: 'Mach-O dynamic linker',
    description: 'Reports dynamic linker paths from LC_LOAD_DYLINKER.',
    fix: 'No action required.',
  ),
  'ios.macho.dyld_environment': RuleDefinition(
    ruleId: 'ios.macho.dyld_environment',
    defaultLevel: FindingLevel.info,
    source: RuleSource.artifact,
    title: 'Mach-O dyld environment',
    description: 'Reports dyld environment strings from LC_DYLD_ENVIRONMENT.',
    fix: 'No action required.',
  ),
  'ios.macho.note': RuleDefinition(
    ruleId: 'ios.macho.note',
    defaultLevel: FindingLevel.info,
    source: RuleSource.artifact,
    title: 'Mach-O note',
    description: 'Reports arbitrary data regions from LC_NOTE.',
    fix: 'No action required.',
  ),
  'ios.macho.linkedit_data': RuleDefinition(
    ruleId: 'ios.macho.linkedit_data',
    defaultLevel: FindingLevel.info,
    source: RuleSource.artifact,
    title: 'Mach-O linkedit data',
    description: 'Reports generic linkedit data command offsets and sizes.',
    fix: 'No action required.',
  ),
  'ios.macho.target_triple': RuleDefinition(
    ruleId: 'ios.macho.target_triple',
    defaultLevel: FindingLevel.info,
    source: RuleSource.artifact,
    title: 'Mach-O target triple',
    description: 'Reports target triples from LC_TARGET_TRIPLE.',
    fix: 'No action required.',
  ),
  'ios.macho.code_signature': RuleDefinition(
    ruleId: 'ios.macho.code_signature',
    defaultLevel: FindingLevel.info,
    source: RuleSource.artifact,
    title: 'Mach-O code signature',
    description: 'Reports LC_CODE_SIGNATURE offset and size metadata.',
    fix: 'No action required.',
  ),
  'ios.macho.encryption_info': RuleDefinition(
    ruleId: 'ios.macho.encryption_info',
    defaultLevel: FindingLevel.info,
    source: RuleSource.artifact,
    title: 'Mach-O encryption info',
    description:
        'Reports LC_ENCRYPTION_INFO offset, size, and crypt id metadata.',
    fix: 'No action required.',
  ),
  'ios.macho.entry_point': RuleDefinition(
    ruleId: 'ios.macho.entry_point',
    defaultLevel: FindingLevel.info,
    source: RuleSource.artifact,
    title: 'Mach-O entry point',
    description: 'Reports LC_MAIN entry offset and stack size metadata.',
    fix: 'No action required.',
  ),
  'ios.macho.chained_fixups': RuleDefinition(
    ruleId: 'ios.macho.chained_fixups',
    defaultLevel: FindingLevel.info,
    source: RuleSource.artifact,
    title: 'Mach-O chained fixups',
    description: 'Reports LC_DYLD_CHAINED_FIXUPS header and starts metadata.',
    fix: 'No action required.',
  ),
  'ios.macho.function_starts': RuleDefinition(
    ruleId: 'ios.macho.function_starts',
    defaultLevel: FindingLevel.info,
    source: RuleSource.artifact,
    title: 'Mach-O function starts',
    description: 'Reports LC_FUNCTION_STARTS offset metadata.',
    fix: 'No action required.',
  ),
  'ios.macho.data_in_code': RuleDefinition(
    ruleId: 'ios.macho.data_in_code',
    defaultLevel: FindingLevel.info,
    source: RuleSource.artifact,
    title: 'Mach-O data in code',
    description: 'Reports LC_DATA_IN_CODE entry metadata.',
    fix: 'No action required.',
  ),
  'ios.permission.camera.empty': RuleDefinition(
    ruleId: 'ios.permission.camera.empty',
    defaultLevel: FindingLevel.failed,
    source: RuleSource.infoPlist,
    title: 'Invalid camera purpose string',
    description: 'NSCameraUsageDescription is empty or placeholder text.',
    fix: 'Replace it with a specific user-facing camera explanation.',
  ),
  'ios.permission.microphone.empty': RuleDefinition(
    ruleId: 'ios.permission.microphone.empty',
    defaultLevel: FindingLevel.failed,
    source: RuleSource.infoPlist,
    title: 'Invalid microphone purpose string',
    description: 'NSMicrophoneUsageDescription is empty or placeholder text.',
    fix: 'Replace it with a specific user-facing microphone explanation.',
  ),
  'ios.permission.photos.empty': RuleDefinition(
    ruleId: 'ios.permission.photos.empty',
    defaultLevel: FindingLevel.failed,
    source: RuleSource.infoPlist,
    title: 'Invalid photo library purpose string',
    description: 'NSPhotoLibraryUsageDescription is empty or placeholder text.',
    fix: 'Replace it with a specific user-facing photo library explanation.',
  ),
  'ios.permission.contacts.empty': RuleDefinition(
    ruleId: 'ios.permission.contacts.empty',
    defaultLevel: FindingLevel.failed,
    source: RuleSource.infoPlist,
    title: 'Invalid contacts purpose string',
    description: 'NSContactsUsageDescription is empty or placeholder text.',
    fix: 'Replace it with a specific user-facing contacts explanation.',
  ),
  'ios.permission.bluetooth.empty': RuleDefinition(
    ruleId: 'ios.permission.bluetooth.empty',
    defaultLevel: FindingLevel.failed,
    source: RuleSource.infoPlist,
    title: 'Invalid bluetooth purpose string',
    description:
        'NSBluetoothAlwaysUsageDescription is empty or placeholder text.',
    fix: 'Replace it with a specific user-facing bluetooth explanation.',
  ),
  'ios.permission.face_id.empty': RuleDefinition(
    ruleId: 'ios.permission.face_id.empty',
    defaultLevel: FindingLevel.failed,
    source: RuleSource.infoPlist,
    title: 'Invalid Face ID purpose string',
    description: 'NSFaceIDUsageDescription is empty or placeholder text.',
    fix: 'Replace it with a specific user-facing Face ID explanation.',
  ),
  'ios.export_compliance.missing': RuleDefinition(
    ruleId: 'ios.export_compliance.missing',
    defaultLevel: FindingLevel.failed,
    source: RuleSource.infoPlist,
    title: 'Missing export compliance flag',
    description: 'ITSAppUsesNonExemptEncryption is missing.',
    fix: 'Add ITSAppUsesNonExemptEncryption with the correct value.',
  ),
  'ios.launch_screen.missing': RuleDefinition(
    ruleId: 'ios.launch_screen.missing',
    defaultLevel: FindingLevel.failed,
    source: RuleSource.infoPlist,
    title: 'Missing launch screen',
    description: 'No launch storyboard or launch screen is declared.',
    fix: 'Configure UILaunchStoryboardName or UILaunchScreen.',
  ),
  'ios.orientations.missing': RuleDefinition(
    ruleId: 'ios.orientations.missing',
    defaultLevel: FindingLevel.failed,
    source: RuleSource.infoPlist,
    title: 'Missing supported orientations',
    description: 'UISupportedInterfaceOrientations is missing or empty.',
    fix: 'Declare at least one supported interface orientation.',
  ),
  'ios.ats.arbitrary_loads': RuleDefinition(
    ruleId: 'ios.ats.arbitrary_loads',
    defaultLevel: FindingLevel.failed,
    source: RuleSource.infoPlist,
    title: 'ATS allows arbitrary loads',
    description: 'NSAllowsArbitraryLoads is enabled.',
    fix: 'Remove the global exception or use narrow exception domains.',
  ),
  'ios.location.always_without_background_mode': RuleDefinition(
    ruleId: 'ios.location.always_without_background_mode',
    defaultLevel: FindingLevel.failed,
    source: RuleSource.infoPlist,
    title: 'Always location lacks background mode',
    description:
        'Always location is declared but UIBackgroundModes lacks location.',
    fix: 'Add location background mode only if the app truly needs it.',
  ),
  'ios.privacy_manifest.invalid': RuleDefinition(
    ruleId: 'ios.privacy_manifest.invalid',
    defaultLevel: FindingLevel.failed,
    source: RuleSource.privacyManifest,
    title: 'Invalid privacy manifest',
    description: 'PrivacyInfo.xcprivacy exists but cannot be parsed.',
    fix: 'Replace it with a valid App Privacy manifest.',
  ),
  'ios.privacy_manifest.invalid_accessed_api_types': RuleDefinition(
    ruleId: 'ios.privacy_manifest.invalid_accessed_api_types',
    defaultLevel: FindingLevel.failed,
    source: RuleSource.privacyManifest,
    title: 'Invalid accessed API declaration',
    description: 'NSPrivacyAccessedAPITypes has an invalid shape.',
    fix: 'Use an array of accessed API type dictionaries.',
  ),
  'ios.privacy_manifest.missing_api_type': RuleDefinition(
    ruleId: 'ios.privacy_manifest.missing_api_type',
    defaultLevel: FindingLevel.failed,
    source: RuleSource.privacyManifest,
    title: 'Missing accessed API type',
    description: 'A privacy manifest entry has no API category.',
    fix: 'Declare the required reason API category.',
  ),
  'ios.privacy_manifest.empty_reasons': RuleDefinition(
    ruleId: 'ios.privacy_manifest.empty_reasons',
    defaultLevel: FindingLevel.failed,
    source: RuleSource.privacyManifest,
    title: 'Missing required reason codes',
    description: 'A required reason API category has no reason codes.',
    fix: 'Add at least one NSPrivacyAccessedAPITypeReasons code.',
  ),
  'ios.privacy_manifest.invalid_reason': RuleDefinition(
    ruleId: 'ios.privacy_manifest.invalid_reason',
    defaultLevel: FindingLevel.failed,
    source: RuleSource.privacyManifest,
    title: 'Invalid required reason code',
    description:
        'A required reason API category declares a reason code Apple does not allow for that category.',
    fix: 'Use a reason code approved for the declared API category.',
  ),
  'ios.permission.contacts.missing': RuleDefinition(
    ruleId: 'ios.permission.contacts.missing',
    defaultLevel: FindingLevel.warned,
    source: RuleSource.binaryEvidence,
    title: 'Contacts API evidence found',
    description: 'Contacts API traces exist without a contacts purpose string.',
    fix: 'Add NSContactsUsageDescription if contacts are reachable.',
  ),
  'ios.permission.camera.missing': RuleDefinition(
    ruleId: 'ios.permission.camera.missing',
    defaultLevel: FindingLevel.warned,
    source: RuleSource.binaryEvidence,
    title: 'Camera API evidence found',
    description: 'Camera API traces exist without a camera purpose string.',
    fix: 'Add NSCameraUsageDescription if camera is reachable.',
  ),
  'ios.permission.microphone.missing': RuleDefinition(
    ruleId: 'ios.permission.microphone.missing',
    defaultLevel: FindingLevel.warned,
    source: RuleSource.binaryEvidence,
    title: 'Microphone API evidence found',
    description:
        'Microphone API traces exist without a microphone purpose string.',
    fix: 'Add NSMicrophoneUsageDescription if microphone is reachable.',
  ),
  'ios.permission.location.missing': RuleDefinition(
    ruleId: 'ios.permission.location.missing',
    defaultLevel: FindingLevel.warned,
    source: RuleSource.binaryEvidence,
    title: 'Location API evidence found',
    description: 'Location API traces exist without a location purpose string.',
    fix: 'Add the matching NSLocation usage description if location is used.',
  ),
  'ios.permission.photos.missing': RuleDefinition(
    ruleId: 'ios.permission.photos.missing',
    defaultLevel: FindingLevel.warned,
    source: RuleSource.binaryEvidence,
    title: 'Photo library API evidence found',
    description: 'Photo API traces exist without a photo purpose string.',
    fix: 'Add the matching photo library usage description if photos are used.',
  ),
  'ios.permission.bluetooth.missing': RuleDefinition(
    ruleId: 'ios.permission.bluetooth.missing',
    defaultLevel: FindingLevel.warned,
    source: RuleSource.binaryEvidence,
    title: 'Bluetooth API evidence found',
    description:
        'Bluetooth API traces exist without a bluetooth purpose string.',
    fix: 'Add NSBluetoothAlwaysUsageDescription if bluetooth is used.',
  ),
  'ios.permission.face_id.missing': RuleDefinition(
    ruleId: 'ios.permission.face_id.missing',
    defaultLevel: FindingLevel.warned,
    source: RuleSource.binaryEvidence,
    title: 'Face ID API evidence found',
    description: 'Face ID API traces exist without a Face ID purpose string.',
    fix: 'Add NSFaceIDUsageDescription if Face ID is used.',
  ),
  'ios.notification.evidence': RuleDefinition(
    ruleId: 'ios.notification.evidence',
    defaultLevel: FindingLevel.warned,
    source: RuleSource.binaryEvidence,
    title: 'Notification evidence found',
    description: 'Notification SDK or API traces were detected.',
    fix: 'Verify authorization flow and push entitlements after signing.',
  ),
  'ios.required_reason.user_defaults': RuleDefinition(
    ruleId: 'ios.required_reason.user_defaults',
    defaultLevel: FindingLevel.warned,
    source: RuleSource.binaryEvidence,
    title: 'UserDefaults Required Reason API evidence found',
    description:
        'UserDefaults traces lack a matching privacy manifest category.',
    fix: 'Declare NSPrivacyAccessedAPICategoryUserDefaults if used.',
  ),
  'ios.required_reason.file_timestamp': RuleDefinition(
    ruleId: 'ios.required_reason.file_timestamp',
    defaultLevel: FindingLevel.warned,
    source: RuleSource.binaryEvidence,
    title: 'File timestamp Required Reason API evidence found',
    description:
        'File timestamp API traces lack a matching privacy manifest category.',
    fix: 'Declare NSPrivacyAccessedAPICategoryFileTimestamp if used.',
  ),
  'ios.required_reason.disk_space': RuleDefinition(
    ruleId: 'ios.required_reason.disk_space',
    defaultLevel: FindingLevel.warned,
    source: RuleSource.binaryEvidence,
    title: 'Disk space Required Reason API evidence found',
    description:
        'Disk space API traces lack a matching privacy manifest category.',
    fix: 'Declare NSPrivacyAccessedAPICategoryDiskSpace if used.',
  ),
  'ios.required_reason.system_boot_time': RuleDefinition(
    ruleId: 'ios.required_reason.system_boot_time',
    defaultLevel: FindingLevel.warned,
    source: RuleSource.binaryEvidence,
    title: 'System boot time Required Reason API evidence found',
    description:
        'System boot time API traces lack a matching privacy manifest category.',
    fix: 'Declare NSPrivacyAccessedAPICategorySystemBootTime if used.',
  ),
  'ios.required_reason.active_keyboards': RuleDefinition(
    ruleId: 'ios.required_reason.active_keyboards',
    defaultLevel: FindingLevel.warned,
    source: RuleSource.binaryEvidence,
    title: 'Active keyboards Required Reason API evidence found',
    description:
        'Active keyboard API traces lack a matching privacy manifest category.',
    fix: 'Declare NSPrivacyAccessedAPICategoryActiveKeyboards if used.',
  ),
  'ios.private_api.uiwebview': RuleDefinition(
    ruleId: 'ios.private_api.uiwebview',
    defaultLevel: FindingLevel.warned,
    source: RuleSource.binaryEvidence,
    title: 'UIWebView evidence found',
    description: 'UIWebView traces were detected.',
    fix: 'Remove old SDKs or code paths that still reference UIWebView.',
  ),
  'ios.private_api.selector': RuleDefinition(
    ruleId: 'ios.private_api.selector',
    defaultLevel: FindingLevel.warned,
    source: RuleSource.binaryEvidence,
    title: 'Private selector evidence found',
    description:
        'Strings that look like private Apple API usage were detected.',
    fix: 'Remove private API references from app code and bundled SDKs.',
  ),
  'ios.private_api.framework': RuleDefinition(
    ruleId: 'ios.private_api.framework',
    defaultLevel: FindingLevel.warned,
    source: RuleSource.binaryEvidence,
    title: 'Private framework link found',
    description: 'A Mach-O load command links a private Apple framework.',
    fix: 'Remove links to private Apple frameworks.',
  ),
  'ios.macho.simulator_slice': RuleDefinition(
    ruleId: 'ios.macho.simulator_slice',
    defaultLevel: FindingLevel.warned,
    source: RuleSource.binaryEvidence,
    title: 'Simulator slice found',
    description:
        'A release artifact binary appears to contain simulator architecture or platform metadata.',
    fix: 'Build a device release artifact and remove simulator slices.',
  ),
  'ios.dynamic_code_execution.evidence': RuleDefinition(
    ruleId: 'ios.dynamic_code_execution.evidence',
    defaultLevel: FindingLevel.warned,
    source: RuleSource.binaryEvidence,
    title: 'Dynamic code execution evidence found',
    description: 'Dynamic loading or script execution traces were detected.',
    fix:
        'Verify this is allowed SDK behavior and does not execute downloaded app code.',
  ),
  'ios.signing.unavailable': RuleDefinition(
    ruleId: 'ios.signing.unavailable',
    defaultLevel: FindingLevel.info,
    source: RuleSource.signing,
    title: 'Signing',
    description: 'The artifact is unsigned, so signing state is unavailable.',
    fix: 'Check signing rules on a signed archive or IPA later.',
  ),
  'ios.signing.present': RuleDefinition(
    ruleId: 'ios.signing.present',
    defaultLevel: FindingLevel.info,
    source: RuleSource.signing,
    title: 'Signing',
    description: 'The artifact appears to contain signing data.',
    fix: 'No action required.',
  ),
};

const findingBuilder = FindingBuilder(ruleRegistry);

LintFinding buildFinding(
  String ruleId, {
  required String message,
  String? path,
  List<String> evidence = const [],
  Map<String, List<String>> evidenceSources = const {},
}) {
  return findingBuilder.build(
    ruleId,
    message: message,
    path: path,
    evidence: evidence,
    evidenceSources: evidenceSources,
  );
}

bool isKnownRule(String ruleId) => ruleRegistry.containsKey(ruleId);
