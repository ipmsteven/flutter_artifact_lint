import 'dart:io';

import 'package:path/path.dart' as p;

import 'macho.dart';

class EvidenceReport {
  const EvidenceReport({
    required this.tokens,
    required this.sourcesByToken,
    required this.scannedFiles,
    required this.architectures,
    required this.buildVersions,
    required this.machOMetadata,
  });

  final Set<String> tokens;
  final Map<String, Set<String>> sourcesByToken;
  final List<String> scannedFiles;
  final List<MachOArchitectureEvidence> architectures;
  final List<MachOBuildVersionEvidence> buildVersions;
  final List<MachOMetadataEvidence> machOMetadata;

  List<String> matched(List<String> candidates) {
    return candidates.where(tokens.contains).toList();
  }

  Map<String, List<String>> sourcesFor(List<String> matchedTokens) {
    final result = <String, List<String>>{};
    for (final token in matchedTokens) {
      final sources = sourcesByToken[token];
      if (sources == null || sources.isEmpty) continue;
      result[token] = sources.toList()..sort();
    }
    return result;
  }
}

class MachOArchitectureEvidence {
  const MachOArchitectureEvidence({
    required this.sourcePath,
    required this.architectures,
  });

  final String sourcePath;
  final List<MachOArchitecture> architectures;
}

class MachOBuildVersionEvidence {
  const MachOBuildVersionEvidence({
    required this.sourcePath,
    required this.buildVersion,
  });

  final String sourcePath;
  final MachOBuildVersion buildVersion;
}

enum MachOMetadataKind { rpath, dylibId, uuid, sourceVersion, codeSignature }

class MachOMetadataEvidence {
  const MachOMetadataEvidence({
    required this.kind,
    required this.sourcePath,
    required this.value,
  });

  final MachOMetadataKind kind;
  final String sourcePath;
  final String value;
}

class IosEvidenceExtractor {
  const IosEvidenceExtractor({
    required this.tokens,
    this.maxBytesPerFile = 16 * 1024 * 1024,
  });

  final List<String> tokens;
  final int maxBytesPerFile;

  EvidenceReport collect(
    String appPath, {
    bool excludeNestedAppExtensions = false,
  }) {
    final found = <String>{};
    final sources = <String, Set<String>>{};
    final scannedFiles = <String>[];
    final architectures = <MachOArchitectureEvidence>[];
    final buildVersions = <MachOBuildVersionEvidence>[];
    final machOMetadata = <MachOMetadataEvidence>[];

    void addEvidence(String token, String sourcePath) {
      found.add(token);
      sources.putIfAbsent(token, () => <String>{}).add(sourcePath);
    }

    for (final entity in Directory(
      appPath,
    ).listSync(recursive: true, followLinks: false)) {
      if (excludeNestedAppExtensions &&
          _isInsideNestedAppExtension(appPath, entity.path)) {
        continue;
      }

      final basename = p.basename(entity.path);
      if (basename.endsWith('.framework')) {
        addEvidence(basename, entity.path);
      }

      if (entity is! File || _shouldSkip(entity.path)) continue;

      scannedFiles.add(entity.path);
      final machoReport = const MachOParser().parseFile(entity);
      if (machoReport.architectures.isNotEmpty) {
        architectures.add(
          MachOArchitectureEvidence(
            sourcePath: entity.path,
            architectures: machoReport.architectures,
          ),
        );
      }

      for (final dylib in machoReport.linkedDylibs) {
        final frameworkToken = _frameworkToken(dylib.path);
        if (frameworkToken != null) addEvidence(frameworkToken, entity.path);
        if (_isPrivateFrameworkPath(dylib.path)) {
          addEvidence(dylib.path, entity.path);
        }
      }

      for (final buildVersion in machoReport.buildVersions) {
        buildVersions.add(
          MachOBuildVersionEvidence(
            sourcePath: entity.path,
            buildVersion: buildVersion,
          ),
        );
      }

      for (final rpath in machoReport.rpaths) {
        machOMetadata.add(
          MachOMetadataEvidence(
            kind: MachOMetadataKind.rpath,
            sourcePath: entity.path,
            value: rpath.path,
          ),
        );
      }

      for (final dylibId in machoReport.dylibIds) {
        machOMetadata.add(
          MachOMetadataEvidence(
            kind: MachOMetadataKind.dylibId,
            sourcePath: entity.path,
            value: dylibId.path,
          ),
        );
      }

      for (final uuid in machoReport.uuids) {
        machOMetadata.add(
          MachOMetadataEvidence(
            kind: MachOMetadataKind.uuid,
            sourcePath: entity.path,
            value: uuid.value,
          ),
        );
      }

      for (final sourceVersion in machoReport.sourceVersions) {
        machOMetadata.add(
          MachOMetadataEvidence(
            kind: MachOMetadataKind.sourceVersion,
            sourcePath: entity.path,
            value: sourceVersion.version,
          ),
        );
      }

      for (final codeSignature in machoReport.codeSignatures) {
        machOMetadata.add(
          MachOMetadataEvidence(
            kind: MachOMetadataKind.codeSignature,
            sourcePath: entity.path,
            value:
                'offset ${codeSignature.dataOffset}, size ${codeSignature.dataSize}',
          ),
        );
      }

      for (final token in _scanTextTokens(
        entity,
        tokens,
        chunkSize: _textChunkSize(maxBytesPerFile),
      )) {
        addEvidence(token, entity.path);
      }
    }

    return EvidenceReport(
      tokens: found,
      sourcesByToken: sources,
      scannedFiles: scannedFiles,
      architectures: architectures,
      buildVersions: buildVersions,
      machOMetadata: machOMetadata,
    );
  }

  bool _shouldSkip(String path) {
    final ext = p.extension(path).toLowerCase();
    return {
      '.png',
      '.jpg',
      '.jpeg',
      '.gif',
      '.webp',
      '.car',
      '.storyboardc',
    }.contains(ext);
  }
}

int _textChunkSize(int maxBytesPerFile) {
  if (maxBytesPerFile <= 0) return 64 * 1024;
  return maxBytesPerFile < 64 * 1024 ? maxBytesPerFile : 64 * 1024;
}

Set<String> _scanTextTokens(
  File file,
  List<String> tokens, {
  required int chunkSize,
}) {
  if (tokens.isEmpty) return const {};

  final found = <String>{};
  final longestToken = tokens
      .map((token) => token.length)
      .fold<int>(0, (longest, length) => length > longest ? length : longest);
  final carryLength = longestToken > 0 ? longestToken - 1 : 0;
  var carry = '';

  try {
    final raf = file.openSync();
    try {
      while (true) {
        final bytes = raf.readSync(chunkSize);
        if (bytes.isEmpty) break;

        final text = carry + _asciiText(bytes);
        for (final token in tokens) {
          if (!found.contains(token) && text.contains(token)) {
            found.add(token);
          }
        }

        if (found.length == tokens.length) break;
        carry = carryLength == 0
            ? ''
            : text.substring(
                text.length > carryLength ? text.length - carryLength : 0,
              );
      }
    } finally {
      raf.closeSync();
    }
  } catch (_) {
    return found;
  }

  return found;
}

String? _frameworkToken(String dylibPath) {
  for (final part in p.split(dylibPath)) {
    if (part.endsWith('.framework')) return part;
  }
  return null;
}

bool _isPrivateFrameworkPath(String dylibPath) {
  return p.split(dylibPath).contains('PrivateFrameworks');
}

bool _isInsideNestedAppExtension(String root, String path) {
  final relative = p.relative(path, from: root);
  if (relative == '.') return false;

  for (final part in p.split(relative)) {
    if (part.endsWith('.appex')) return true;
  }
  return false;
}

String _asciiText(List<int> bytes) {
  final buffer = StringBuffer();
  for (final byte in bytes) {
    if (byte == 0x09 || byte == 0x0a || byte == 0x0d) {
      buffer.writeCharCode(0x20);
    } else if (byte >= 0x20 && byte <= 0x7e) {
      buffer.writeCharCode(byte);
    } else {
      buffer.writeCharCode(0x20);
    }
  }
  return buffer.toString();
}
