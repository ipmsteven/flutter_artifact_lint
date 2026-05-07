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

enum MachOMetadataKind {
  header,
  rpath,
  dylibId,
  uuid,
  sourceVersion,
  linkerOption,
  dylinker,
  dyldEnvironment,
  note,
  linkeditData,
  targetTriple,
  subCommand,
  filesetEntry,
  codeSignature,
  encryptionInfo,
  entryPoint,
  routines,
  twolevelHints,
  prebindChecksum,
  chainedFixups,
  functionStarts,
  dataInCode,
}

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

      for (final header in machoReport.headers) {
        machOMetadata.add(
          MachOMetadataEvidence(
            kind: MachOMetadataKind.header,
            sourcePath: entity.path,
            value: _machoHeaderValue(header),
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

      for (final linkerOption in machoReport.linkerOptions) {
        machOMetadata.add(
          MachOMetadataEvidence(
            kind: MachOMetadataKind.linkerOption,
            sourcePath: entity.path,
            value: linkerOption.values.join(' '),
          ),
        );
      }

      for (final dylinker in machoReport.dylinkers) {
        machOMetadata.add(
          MachOMetadataEvidence(
            kind: MachOMetadataKind.dylinker,
            sourcePath: entity.path,
            value: _dylinkerValue(dylinker),
          ),
        );
      }

      for (final environment in machoReport.dyldEnvironments) {
        machOMetadata.add(
          MachOMetadataEvidence(
            kind: MachOMetadataKind.dyldEnvironment,
            sourcePath: entity.path,
            value: environment.value,
          ),
        );
      }

      for (final note in machoReport.notes) {
        machOMetadata.add(
          MachOMetadataEvidence(
            kind: MachOMetadataKind.note,
            sourcePath: entity.path,
            value: _noteValue(note),
          ),
        );
      }

      for (final data in machoReport.linkeditData) {
        machOMetadata.add(
          MachOMetadataEvidence(
            kind: MachOMetadataKind.linkeditData,
            sourcePath: entity.path,
            value: _linkeditDataValue(data),
          ),
        );
      }

      for (final triple in machoReport.targetTriples) {
        machOMetadata.add(
          MachOMetadataEvidence(
            kind: MachOMetadataKind.targetTriple,
            sourcePath: entity.path,
            value: triple.value,
          ),
        );
      }

      for (final subCommand in machoReport.subCommands) {
        machOMetadata.add(
          MachOMetadataEvidence(
            kind: MachOMetadataKind.subCommand,
            sourcePath: entity.path,
            value: '${subCommand.commandName}: ${subCommand.value}',
          ),
        );
      }

      for (final entry in machoReport.filesetEntries) {
        machOMetadata.add(
          MachOMetadataEvidence(
            kind: MachOMetadataKind.filesetEntry,
            sourcePath: entity.path,
            value: _filesetEntryValue(entry),
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

      for (final encryptionInfo in machoReport.encryptionInfos) {
        machOMetadata.add(
          MachOMetadataEvidence(
            kind: MachOMetadataKind.encryptionInfo,
            sourcePath: entity.path,
            value:
                'offset ${encryptionInfo.cryptOffset}, size ${encryptionInfo.cryptSize}, crypt id ${encryptionInfo.cryptId}',
          ),
        );
      }

      for (final entryPoint in machoReport.entryPoints) {
        machOMetadata.add(
          MachOMetadataEvidence(
            kind: MachOMetadataKind.entryPoint,
            sourcePath: entity.path,
            value:
                'entry offset ${entryPoint.entryOffset}, stack size ${entryPoint.stackSize}',
          ),
        );
      }

      for (final routines in machoReport.routines) {
        machOMetadata.add(
          MachOMetadataEvidence(
            kind: MachOMetadataKind.routines,
            sourcePath: entity.path,
            value: _routinesValue(routines),
          ),
        );
      }

      for (final hints in machoReport.twolevelHints) {
        machOMetadata.add(
          MachOMetadataEvidence(
            kind: MachOMetadataKind.twolevelHints,
            sourcePath: entity.path,
            value: _twolevelHintsValue(hints),
          ),
        );
      }

      for (final checksum in machoReport.prebindChecksums) {
        machOMetadata.add(
          MachOMetadataEvidence(
            kind: MachOMetadataKind.prebindChecksum,
            sourcePath: entity.path,
            value: _prebindChecksumValue(checksum),
          ),
        );
      }

      for (final chainedFixup in machoReport.chainedFixups) {
        if (chainedFixup.fixupsVersion == null) continue;

        machOMetadata.add(
          MachOMetadataEvidence(
            kind: MachOMetadataKind.chainedFixups,
            sourcePath: entity.path,
            value: _chainedFixupsValue(chainedFixup),
          ),
        );
      }

      for (final functionStarts in machoReport.functionStarts) {
        machOMetadata.add(
          MachOMetadataEvidence(
            kind: MachOMetadataKind.functionStarts,
            sourcePath: entity.path,
            value: _functionStartsValue(functionStarts),
          ),
        );
      }

      for (final dataInCode in machoReport.dataInCode) {
        machOMetadata.add(
          MachOMetadataEvidence(
            kind: MachOMetadataKind.dataInCode,
            sourcePath: entity.path,
            value: _dataInCodeValue(dataInCode),
          ),
        );
      }

      for (final sectionString in machoReport.sectionStrings) {
        for (final token in _matchedTokens(sectionString.value, tokens)) {
          addEvidence(token, '${entity.path}#${sectionString.sectionName}');
        }
      }

      for (final swiftType in machoReport.swiftTypes) {
        for (final token in _matchedTokens(swiftType.name, tokens)) {
          addEvidence(token, '${entity.path}#${swiftType.sourceSection}');
        }
      }

      for (final protocol in machoReport.swiftProtocols) {
        for (final token in _matchedTokens(protocol.name, tokens)) {
          addEvidence(token, '${entity.path}#${protocol.sourceSection}');
        }
      }

      for (final conformance in machoReport.swiftProtocolConformances) {
        for (final token in _matchedTokens(conformance.typeName, tokens)) {
          addEvidence(token, '${entity.path}#${conformance.sourceSection}');
        }
        for (final token in _matchedTokens(conformance.protocolName, tokens)) {
          addEvidence(token, '${entity.path}#${conformance.sourceSection}');
        }
      }

      for (final field in machoReport.swiftFields) {
        for (final token in _matchedTokens(field.name, tokens)) {
          addEvidence(token, '${entity.path}#${field.sourceSection}');
        }
        final ownerTypeName = field.ownerTypeName;
        if (ownerTypeName != null) {
          for (final token in _matchedTokens(ownerTypeName, tokens)) {
            addEvidence(token, '${entity.path}#${field.sourceSection}');
          }
        }
        final superclassTypeName = field.superclassTypeName;
        if (superclassTypeName != null) {
          for (final token in _matchedTokens(superclassTypeName, tokens)) {
            addEvidence(token, '${entity.path}#${field.sourceSection}');
          }
        }
        final fieldTypeName = field.fieldTypeName;
        if (fieldTypeName != null) {
          for (final token in _matchedTokens(fieldTypeName, tokens)) {
            addEvidence(token, '${entity.path}#${field.sourceSection}');
          }
        }
      }

      for (final symbol in machoReport.symbols) {
        for (final token in _matchedTokens(symbol.name, tokens)) {
          addEvidence(token, '${entity.path}#LC_SYMTAB');
        }
      }

      for (final symbol in machoReport.dyldBindSymbols) {
        for (final token in _matchedTokens(symbol.name, tokens)) {
          addEvidence(token, '${entity.path}#${symbol.source}');
        }
      }

      for (final symbol in machoReport.dyldExportSymbols) {
        for (final token in _matchedTokens(symbol.name, tokens)) {
          addEvidence(token, '${entity.path}#${symbol.source}');
        }
      }

      for (final selector in machoReport.objcSelectors) {
        for (final token in _matchedTokens(selector.name, tokens)) {
          addEvidence(token, '${entity.path}#${selector.sourceSection}');
        }
      }

      for (final objcClass in machoReport.objcClasses) {
        for (final token in _matchedTokens(objcClass.name, tokens)) {
          addEvidence(token, '${entity.path}#${objcClass.sourceSection}');
        }
        final superclassName = objcClass.superclassName;
        if (superclassName != null) {
          for (final token in _matchedTokens(superclassName, tokens)) {
            addEvidence(token, '${entity.path}#${objcClass.sourceSection}');
          }
        }
      }

      for (final category in machoReport.objcCategories) {
        for (final token in _matchedTokens(category.name, tokens)) {
          addEvidence(token, '${entity.path}#${category.sourceSection}');
        }
        final className = category.className;
        if (className != null) {
          for (final token in _matchedTokens(className, tokens)) {
            addEvidence(token, '${entity.path}#${category.sourceSection}');
          }
        }
      }

      for (final objcProtocol in machoReport.objcProtocols) {
        for (final token in _matchedTokens(objcProtocol.name, tokens)) {
          addEvidence(token, '${entity.path}#${objcProtocol.sourceSection}');
        }
      }

      for (final objcMethod in machoReport.objcMethods) {
        for (final token in _matchedTokens(objcMethod.name, tokens)) {
          addEvidence(token, '${entity.path}#${objcMethod.sourceSection}');
        }
      }

      for (final ivar in machoReport.objcIvars) {
        for (final token in _matchedTokens(ivar.name, tokens)) {
          addEvidence(token, '${entity.path}#${ivar.sourceSection}');
        }
        for (final token in _matchedTokens(ivar.typeEncoding, tokens)) {
          addEvidence(token, '${entity.path}#${ivar.sourceSection}');
        }
      }

      for (final property in machoReport.objcProperties) {
        for (final token in _matchedTokens(property.name, tokens)) {
          addEvidence(token, '${entity.path}#${property.sourceSection}');
        }
        for (final token in _matchedTokens(property.attributes, tokens)) {
          addEvidence(token, '${entity.path}#${property.sourceSection}');
        }
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

Iterable<String> _matchedTokens(String value, List<String> tokens) sync* {
  for (final token in tokens) {
    if (value.contains(token)) yield token;
  }
}

String _machoHeaderValue(MachOHeaderInfo header) {
  final flags = header.flagNames;
  return [
    header.is64Bit ? '64-bit' : '32-bit',
    header.fileTypeName,
    if (flags.isEmpty) 'flags none' else 'flags ${flags.join(', ')}',
  ].join('; ');
}

String _noteValue(MachONote note) {
  return 'owner ${note.owner}; offset ${note.dataOffset}; size ${note.dataSize}';
}

String _linkeditDataValue(MachOLinkeditData data) {
  return '${data.commandName}; offset ${data.dataOffset}; size ${data.dataSize}';
}

String _dylinkerValue(MachODylinker dylinker) {
  return '${dylinker.commandName}; ${dylinker.path}';
}

String _routinesValue(MachORoutines routines) {
  return [
    routines.commandName,
    'init address ${routines.initAddress}',
    'init module ${routines.initModule}',
  ].join('; ');
}

String _twolevelHintsValue(MachOTwolevelHints hints) {
  return 'offset ${hints.offset}; hints ${hints.hintsCount}';
}

String _prebindChecksumValue(MachOPrebindChecksum checksum) {
  return 'checksum ${checksum.checksum}';
}

String _filesetEntryValue(MachOFilesetEntry entry) {
  return [
    entry.entryId,
    'vm address ${entry.vmAddress}',
    'file offset ${entry.fileOffset}',
  ].join('; ');
}

String _chainedFixupsValue(MachOChainedFixups chainedFixup) {
  final segmentValues = [
    for (final segment in chainedFixup.segments)
      'pointer format ${segment.pointerFormat}, page size ${segment.pageSize}, segment offset ${segment.segmentOffset}, pages ${segment.pageStarts.length}',
  ];
  return [
    'version ${chainedFixup.fixupsVersion}',
    'imports ${chainedFixup.importsCount}',
    'imports format ${chainedFixup.importsFormat}',
    'symbols format ${chainedFixup.symbolsFormat}',
    ...segmentValues,
  ].join('; ');
}

String _functionStartsValue(MachOFunctionStarts functionStarts) {
  final offsets = functionStarts.offsets;
  return [
    'count ${offsets.length}',
    'data size ${functionStarts.dataSize}',
    if (offsets.isNotEmpty) 'first offset ${offsets.first}',
    if (offsets.isNotEmpty) 'last offset ${offsets.last}',
  ].join('; ');
}

String _dataInCodeValue(MachODataInCode dataInCode) {
  final kindNames =
      dataInCode.entries.map((entry) => entry.kindName).toSet().toList()
        ..sort();
  return [
    'entries ${dataInCode.entries.length}',
    'data size ${dataInCode.dataSize}',
    if (kindNames.isNotEmpty) 'kinds ${kindNames.join(', ')}',
  ].join('; ');
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
