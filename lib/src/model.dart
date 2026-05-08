enum ArtifactType { unsignedApp, signedApp, xcarchive }

enum FindingLevel { failed, warned, info }

enum FailOn { failed, warned, none }

enum EvidenceSourceKind {
  bundleDirectory,
  plainText,
  machoLinkedDylib,
  machoSectionString,
  machoSwiftType,
  machoSwiftProtocol,
  machoSwiftProtocolConformance,
  machoSwiftField,
  machoSymbolTable,
  machoDyldBindSymbol,
  machoDyldExportSymbol,
  machoObjcSelector,
  machoObjcClass,
  machoObjcCategory,
  machoObjcProtocol,
  machoObjcMethod,
  machoObjcIvar,
  machoObjcProperty,
}

class EvidenceSource {
  const EvidenceSource({required this.kind, required this.path, this.location});

  final EvidenceSourceKind kind;
  final String path;
  final String? location;

  String get displayPath =>
      location == null || location!.isEmpty ? path : '$path#$location';

  Map<String, Object?> toJson() => {
    'kind': kind.name,
    'path': path,
    if (location != null && location!.isNotEmpty) 'location': location,
  };

  @override
  bool operator ==(Object other) {
    return other is EvidenceSource &&
        other.kind == kind &&
        other.path == path &&
        other.location == location;
  }

  @override
  int get hashCode => Object.hash(kind, path, location);
}

class IosArtifact {
  const IosArtifact({
    required this.path,
    required this.appPath,
    required this.type,
  });

  final String path;
  final String appPath;
  final ArtifactType type;

  String get displayType => switch (type) {
    ArtifactType.unsignedApp => 'unsigned app',
    ArtifactType.signedApp => 'signed app',
    ArtifactType.xcarchive => 'xcarchive',
  };
}

class LintFinding {
  const LintFinding({
    required this.level,
    required this.ruleId,
    required this.title,
    required this.message,
    this.fix,
    this.path,
    this.evidence = const [],
    this.evidenceSources = const {},
    this.evidenceSourceDetails = const {},
  });

  final FindingLevel level;
  final String ruleId;
  final String title;
  final String message;
  final String? fix;
  final String? path;
  final List<String> evidence;
  final Map<String, List<String>> evidenceSources;
  final Map<String, List<EvidenceSource>> evidenceSourceDetails;

  Map<String, Object?> toJson() => {
    'level': level.name,
    'ruleId': ruleId,
    'title': title,
    'message': message,
    if (fix != null) 'fix': fix,
    if (path != null) 'path': path,
    if (evidence.isNotEmpty) 'evidence': evidence,
    if (evidenceSources.isNotEmpty) 'evidenceSources': evidenceSources,
    if (evidenceSourceDetails.isNotEmpty)
      'evidenceSourceDetails': evidenceSourceDetails.map(
        (token, sources) =>
            MapEntry(token, sources.map((source) => source.toJson()).toList()),
      ),
  };
}

class ScanResult {
  const ScanResult({
    required this.artifact,
    required this.findings,
    this.suppressedCount = 0,
  });

  final IosArtifact artifact;
  final List<LintFinding> findings;
  final int suppressedCount;

  List<LintFinding> get failed => findings
      .where((finding) => finding.level == FindingLevel.failed)
      .toList();

  List<LintFinding> get warned => findings
      .where((finding) => finding.level == FindingLevel.warned)
      .toList();

  List<LintFinding> get info =>
      findings.where((finding) => finding.level == FindingLevel.info).toList();

  String resultFor(FailOn failOn) {
    if (failed.isNotEmpty) return 'FAILED';
    if (warned.isNotEmpty && failOn == FailOn.warned) return 'WARNED';
    return 'PASSED';
  }

  int exitCodeFor(FailOn failOn) {
    if (failOn == FailOn.none) return 0;
    if (failed.isNotEmpty) return 1;
    if (failOn == FailOn.warned && warned.isNotEmpty) return 1;
    return 0;
  }

  Map<String, Object?> toJson(FailOn failOn) => {
    'result': resultFor(failOn),
    'artifact': artifact.path,
    'appPath': artifact.appPath,
    'artifactType': artifact.type.name,
    'failedCount': failed.length,
    'warnedCount': warned.length,
    'infoCount': info.length,
    'suppressedCount': suppressedCount,
    'findings': findings.map((finding) => finding.toJson()).toList(),
  };

  ScanResult copyWith({
    IosArtifact? artifact,
    List<LintFinding>? findings,
    int? suppressedCount,
  }) {
    return ScanResult(
      artifact: artifact ?? this.artifact,
      findings: findings ?? this.findings,
      suppressedCount: suppressedCount ?? this.suppressedCount,
    );
  }
}
