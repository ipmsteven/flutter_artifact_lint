import 'dart:convert';
import 'dart:io';

class MachOReport {
  const MachOReport({
    required this.linkedDylibs,
    this.architectures = const [],
    this.buildVersions = const [],
    this.rpaths = const [],
    this.dylibIds = const [],
    this.uuids = const [],
    this.sourceVersions = const [],
    this.codeSignatures = const [],
    this.segments = const [],
    this.symbolTables = const [],
    this.symbols = const [],
    this.sectionStrings = const [],
    this.dynamicSymbolTables = const [],
    this.objcSelectors = const [],
    this.objcClasses = const [],
    this.objcMethods = const [],
  });

  final List<MachODylib> linkedDylibs;
  final List<MachOArchitecture> architectures;
  final List<MachOBuildVersion> buildVersions;
  final List<MachORpath> rpaths;
  final List<MachODylibId> dylibIds;
  final List<MachOUuid> uuids;
  final List<MachOSourceVersion> sourceVersions;
  final List<MachOCodeSignature> codeSignatures;
  final List<MachOSegment> segments;
  final List<MachOSymbolTable> symbolTables;
  final List<MachOSymbol> symbols;
  final List<MachOSectionString> sectionStrings;
  final List<MachODynamicSymbolTable> dynamicSymbolTables;
  final List<MachOObjCSelector> objcSelectors;
  final List<MachOObjCClass> objcClasses;
  final List<MachOObjCMethod> objcMethods;
}

class MachODylib {
  const MachODylib({required this.path, required this.weak});

  final String path;
  final bool weak;
}

class MachOArchitecture {
  const MachOArchitecture({required this.cpuType, required this.cpuSubtype});

  final int cpuType;
  final int cpuSubtype;

  int get normalizedCpuSubtype => cpuSubtype & 0x00ffffff;

  String get name => switch (cpuType) {
    0x0100000c => normalizedCpuSubtype == 2 ? 'arm64e' : 'arm64',
    0x01000007 => 'x86_64',
    12 => 'arm',
    7 => 'i386',
    _ => 'cpu $cpuType subtype $cpuSubtype',
  };
}

class MachOBuildVersion {
  const MachOBuildVersion({
    required this.platform,
    required this.minimumOsVersion,
    required this.sdkVersion,
  });

  final int platform;
  final String minimumOsVersion;
  final String sdkVersion;

  String get platformName => switch (platform) {
    1 => 'macOS',
    2 => 'iOS',
    3 => 'tvOS',
    4 => 'watchOS',
    5 => 'bridgeOS',
    6 => 'Mac Catalyst',
    7 => 'iOS Simulator',
    8 => 'tvOS Simulator',
    9 => 'watchOS Simulator',
    10 => 'DriverKit',
    11 => 'visionOS',
    12 => 'visionOS Simulator',
    _ => 'platform $platform',
  };
}

class MachORpath {
  const MachORpath({required this.path});

  final String path;
}

class MachODylibId {
  const MachODylibId({required this.path});

  final String path;
}

class MachOUuid {
  const MachOUuid({required this.value});

  final String value;
}

class MachOSourceVersion {
  const MachOSourceVersion({required this.version});

  final String version;
}

class MachOCodeSignature {
  const MachOCodeSignature({required this.dataOffset, required this.dataSize});

  final int dataOffset;
  final int dataSize;
}

class MachOSegment {
  const MachOSegment({required this.name, required this.sections});

  final String name;
  final List<MachOSection> sections;
}

class MachOSection {
  const MachOSection({
    required this.segmentName,
    required this.name,
    this.address = 0,
    this.size = 0,
    this.fileOffset = 0,
    this.flags = 0,
  });

  final String segmentName;
  final String name;
  final int address;
  final int size;
  final int fileOffset;
  final int flags;

  String get displayName => '$segmentName.$name';
}

class MachOSectionString {
  const MachOSectionString({required this.sectionName, required this.value});

  final String sectionName;
  final String value;
}

class MachOObjCSelector {
  const MachOObjCSelector({
    required this.name,
    required this.sourceSection,
    required this.targetAddress,
  });

  final String name;
  final String sourceSection;
  final int targetAddress;
}

class MachOObjCClass {
  const MachOObjCClass({
    required this.name,
    required this.sourceSection,
    required this.classAddress,
  });

  final String name;
  final String sourceSection;
  final int classAddress;
}

class MachOObjCMethod {
  const MachOObjCMethod({
    required this.name,
    required this.className,
    required this.sourceSection,
    required this.methodListAddress,
  });

  final String name;
  final String className;
  final String sourceSection;
  final int methodListAddress;
}

class MachOSymbolTable {
  const MachOSymbolTable({
    required this.symbolOffset,
    required this.symbolCount,
    required this.stringOffset,
    required this.stringSize,
  });

  final int symbolOffset;
  final int symbolCount;
  final int stringOffset;
  final int stringSize;
}

class MachODynamicSymbolTable {
  const MachODynamicSymbolTable({
    required this.localSymbolIndex,
    required this.localSymbolCount,
    required this.externalSymbolIndex,
    required this.externalSymbolCount,
    required this.undefinedSymbolIndex,
    required this.undefinedSymbolCount,
    required this.indirectSymbolOffset,
    required this.indirectSymbolCount,
  });

  final int localSymbolIndex;
  final int localSymbolCount;
  final int externalSymbolIndex;
  final int externalSymbolCount;
  final int undefinedSymbolIndex;
  final int undefinedSymbolCount;
  final int indirectSymbolOffset;
  final int indirectSymbolCount;
}

class MachOSymbol {
  const MachOSymbol({
    required this.name,
    required this.type,
    required this.sectionIndex,
    required this.description,
    required this.value,
  });

  final String name;
  final int type;
  final int sectionIndex;
  final int description;
  final int value;
}

class MachOParser {
  const MachOParser();

  MachOReport parseFile(File file) {
    try {
      final raf = file.openSync();
      try {
        return _parseRandomAccessFile(raf);
      } finally {
        raf.closeSync();
      }
    } catch (_) {
      return const MachOReport(linkedDylibs: []);
    }
  }

  MachOReport parse(List<int> bytes) {
    final fatReport = _parseFat(bytes);
    if (fatReport != null) return fatReport;

    final thinReport = _parseThin(bytes);
    return _deduplicatedReport(
      thinReport.linkedDylibs,
      thinReport.architectures,
      thinReport.buildVersions,
      thinReport.rpaths,
      thinReport.dylibIds,
      thinReport.uuids,
      thinReport.sourceVersions,
      thinReport.codeSignatures,
      thinReport.segments,
      thinReport.symbolTables,
      thinReport.symbols,
      thinReport.sectionStrings,
      thinReport.dynamicSymbolTables,
      thinReport.objcSelectors,
      thinReport.objcClasses,
      thinReport.objcMethods,
    );
  }

  MachOReport _parseRandomAccessFile(RandomAccessFile raf) {
    final fileLength = raf.lengthSync();
    final prefix = _readRange(raf, 0, fileLength < 8 ? fileLength : 8);
    if (prefix.length < 8) {
      return const MachOReport(linkedDylibs: []);
    }

    final magic = _readU32be(prefix, 0);
    final fat64 = switch (magic) {
      _fatMagic => false,
      _fatMagic64 => true,
      _ => null,
    };
    if (fat64 == null) {
      return _parseThinFileAt(raf, 0, fileLength);
    }

    final architectureCount = _readU32be(prefix, 4);
    final archSize = fat64 ? 32 : 20;
    final archTableSize = architectureCount * archSize;
    final archTable = _readRange(
      raf,
      8,
      archTableSize > _maxFatArchTableBytes
          ? _maxFatArchTableBytes
          : archTableSize,
    );
    final linkedDylibs = <MachODylib>[];
    final architectures = <MachOArchitecture>[];
    final buildVersions = <MachOBuildVersion>[];
    final rpaths = <MachORpath>[];
    final dylibIds = <MachODylibId>[];
    final uuids = <MachOUuid>[];
    final sourceVersions = <MachOSourceVersion>[];
    final codeSignatures = <MachOCodeSignature>[];
    final segments = <MachOSegment>[];
    final symbolTables = <MachOSymbolTable>[];
    final symbols = <MachOSymbol>[];
    final sectionStrings = <MachOSectionString>[];
    final dynamicSymbolTables = <MachODynamicSymbolTable>[];
    final objcSelectors = <MachOObjCSelector>[];
    final objcClasses = <MachOObjCClass>[];
    final objcMethods = <MachOObjCMethod>[];

    for (
      var offset = 0;
      offset + archSize <= archTable.length;
      offset += archSize
    ) {
      final sliceOffset = fat64
          ? _readU64be(archTable, offset + 8)
          : _readU32be(archTable, offset + 8);
      final sliceSize = fat64
          ? _readU64be(archTable, offset + 16)
          : _readU32be(archTable, offset + 12);
      if (sliceOffset <= 0 ||
          sliceSize <= 0 ||
          sliceOffset + sliceSize > fileLength) {
        continue;
      }

      final sliceReport = _parseThinFileAt(raf, sliceOffset, sliceSize);
      linkedDylibs.addAll(sliceReport.linkedDylibs);
      architectures.addAll(sliceReport.architectures);
      buildVersions.addAll(sliceReport.buildVersions);
      rpaths.addAll(sliceReport.rpaths);
      dylibIds.addAll(sliceReport.dylibIds);
      uuids.addAll(sliceReport.uuids);
      sourceVersions.addAll(sliceReport.sourceVersions);
      codeSignatures.addAll(sliceReport.codeSignatures);
      segments.addAll(sliceReport.segments);
      symbolTables.addAll(sliceReport.symbolTables);
      symbols.addAll(sliceReport.symbols);
      sectionStrings.addAll(sliceReport.sectionStrings);
      dynamicSymbolTables.addAll(sliceReport.dynamicSymbolTables);
      objcSelectors.addAll(sliceReport.objcSelectors);
      objcClasses.addAll(sliceReport.objcClasses);
      objcMethods.addAll(sliceReport.objcMethods);
    }

    return _deduplicatedReport(
      linkedDylibs,
      architectures,
      buildVersions,
      rpaths,
      dylibIds,
      uuids,
      sourceVersions,
      codeSignatures,
      segments,
      symbolTables,
      symbols,
      sectionStrings,
      dynamicSymbolTables,
      objcSelectors,
      objcClasses,
      objcMethods,
    );
  }

  MachOReport _parseThinFileAt(
    RandomAccessFile raf,
    int fileOffset,
    int availableLength,
  ) {
    final headerPrefix = _readRange(
      raf,
      fileOffset,
      availableLength < 32 ? availableLength : 32,
    );
    if (headerPrefix.length < 28) {
      return const MachOReport(linkedDylibs: []);
    }

    final magic = _readU32(headerPrefix, 0);
    final is64Bit = switch (magic) {
      _mhMagic64 => true,
      _mhMagic => false,
      _ => null,
    };
    final headerSize = switch (is64Bit) {
      true => 32,
      false => 28,
      null => null,
    };
    if (headerSize == null || headerPrefix.length < headerSize) {
      return const MachOReport(linkedDylibs: []);
    }
    final thinIs64Bit = is64Bit == true;

    final sizeofcmds = _readU32(headerPrefix, 20);
    final commandBytes = sizeofcmds > _maxLoadCommandBytes
        ? _maxLoadCommandBytes
        : sizeofcmds;
    final thinBytes = _readRange(
      raf,
      fileOffset,
      _boundedEnd(headerSize, commandBytes, availableLength),
    );
    final report = _parseThin(thinBytes);
    final symbols = _readSymbolsFromFile(
      raf,
      fileOffset,
      availableLength,
      is64Bit: thinIs64Bit,
      symbolTables: report.symbolTables,
    );
    final sectionStrings = _readSectionStringsFromFile(
      raf,
      fileOffset,
      availableLength,
      segments: report.segments,
    );
    final objcSelectors = _readObjCSelectorsFromFile(
      raf,
      fileOffset,
      availableLength,
      is64Bit: thinIs64Bit,
      segments: report.segments,
    );
    final objcClasses = _readObjCClassesFromFile(
      raf,
      fileOffset,
      availableLength,
      is64Bit: thinIs64Bit,
      segments: report.segments,
    );
    final objcMethods = _readObjCMethodsFromFile(
      raf,
      fileOffset,
      availableLength,
      is64Bit: thinIs64Bit,
      segments: report.segments,
    );
    if (symbols.isEmpty &&
        sectionStrings.isEmpty &&
        objcSelectors.isEmpty &&
        objcClasses.isEmpty &&
        objcMethods.isEmpty) {
      return report;
    }

    return _deduplicatedReport(
      report.linkedDylibs,
      report.architectures,
      report.buildVersions,
      report.rpaths,
      report.dylibIds,
      report.uuids,
      report.sourceVersions,
      report.codeSignatures,
      report.segments,
      report.symbolTables,
      [...report.symbols, ...symbols],
      [...report.sectionStrings, ...sectionStrings],
      report.dynamicSymbolTables,
      [...report.objcSelectors, ...objcSelectors],
      [...report.objcClasses, ...objcClasses],
      [...report.objcMethods, ...objcMethods],
    );
  }

  MachOReport? _parseFat(List<int> bytes) {
    if (bytes.length < 8) return null;

    final magic = _readU32be(bytes, 0);
    final fat64 = switch (magic) {
      _fatMagic => false,
      _fatMagic64 => true,
      _ => null,
    };
    if (fat64 == null) {
      return null;
    }

    final architectureCount = _readU32be(bytes, 4);
    final archSize = fat64 ? 32 : 20;
    var offset = 8;
    final linkedDylibs = <MachODylib>[];
    final architectures = <MachOArchitecture>[];
    final buildVersions = <MachOBuildVersion>[];
    final rpaths = <MachORpath>[];
    final dylibIds = <MachODylibId>[];
    final uuids = <MachOUuid>[];
    final sourceVersions = <MachOSourceVersion>[];
    final codeSignatures = <MachOCodeSignature>[];
    final segments = <MachOSegment>[];
    final symbolTables = <MachOSymbolTable>[];
    final symbols = <MachOSymbol>[];
    final sectionStrings = <MachOSectionString>[];
    final dynamicSymbolTables = <MachODynamicSymbolTable>[];
    final objcSelectors = <MachOObjCSelector>[];
    final objcClasses = <MachOObjCClass>[];
    final objcMethods = <MachOObjCMethod>[];

    for (var i = 0; i < architectureCount; i += 1) {
      if (offset + archSize > bytes.length) break;

      final sliceOffset = fat64
          ? _readU64be(bytes, offset + 8)
          : _readU32be(bytes, offset + 8);
      final sliceSize = fat64
          ? _readU64be(bytes, offset + 16)
          : _readU32be(bytes, offset + 12);
      if (sliceOffset > 0 &&
          sliceSize > 0 &&
          sliceOffset + sliceSize <= bytes.length) {
        final sliceReport = _parseThin(
          bytes.sublist(sliceOffset, sliceOffset + sliceSize),
        );
        linkedDylibs.addAll(sliceReport.linkedDylibs);
        architectures.addAll(sliceReport.architectures);
        buildVersions.addAll(sliceReport.buildVersions);
        rpaths.addAll(sliceReport.rpaths);
        dylibIds.addAll(sliceReport.dylibIds);
        uuids.addAll(sliceReport.uuids);
        sourceVersions.addAll(sliceReport.sourceVersions);
        codeSignatures.addAll(sliceReport.codeSignatures);
        segments.addAll(sliceReport.segments);
        symbolTables.addAll(sliceReport.symbolTables);
        symbols.addAll(sliceReport.symbols);
        sectionStrings.addAll(sliceReport.sectionStrings);
        dynamicSymbolTables.addAll(sliceReport.dynamicSymbolTables);
        objcSelectors.addAll(sliceReport.objcSelectors);
        objcClasses.addAll(sliceReport.objcClasses);
        objcMethods.addAll(sliceReport.objcMethods);
      }

      offset += archSize;
    }

    return _deduplicatedReport(
      linkedDylibs,
      architectures,
      buildVersions,
      rpaths,
      dylibIds,
      uuids,
      sourceVersions,
      codeSignatures,
      segments,
      symbolTables,
      symbols,
      sectionStrings,
      dynamicSymbolTables,
      objcSelectors,
      objcClasses,
      objcMethods,
    );
  }

  MachOReport _parseThin(List<int> bytes) {
    final header = _readHeader(bytes);
    if (header == null) {
      return const MachOReport(linkedDylibs: []);
    }

    final linkedDylibs = <MachODylib>[];
    final architectures = [
      MachOArchitecture(cpuType: header.cpuType, cpuSubtype: header.cpuSubtype),
    ];
    final buildVersions = <MachOBuildVersion>[];
    final rpaths = <MachORpath>[];
    final dylibIds = <MachODylibId>[];
    final uuids = <MachOUuid>[];
    final sourceVersions = <MachOSourceVersion>[];
    final codeSignatures = <MachOCodeSignature>[];
    final segments = <MachOSegment>[];
    final symbolTables = <MachOSymbolTable>[];
    final dynamicSymbolTables = <MachODynamicSymbolTable>[];
    var offset = header.loadCommandsOffset;

    for (var i = 0; i < header.commandCount; i += 1) {
      if (offset + 8 > header.loadCommandsEnd) break;

      final command = _readU32(bytes, offset);
      final commandSize = _readU32(bytes, offset + 4);
      if (commandSize < 8 || offset + commandSize > header.loadCommandsEnd) {
        break;
      }

      if (_isDylibLoadCommand(command) && commandSize >= 24) {
        final path = _readCommandString(
          bytes,
          commandOffset: offset,
          commandSize: commandSize,
          stringOffsetField: 8,
          minimumStringOffset: 24,
        );
        if (path != null) {
          linkedDylibs.add(
            MachODylib(path: path, weak: command == _lcLoadWeakDylib),
          );
        }
      }

      if (command == _lcIdDylib && commandSize >= 24) {
        final path = _readCommandString(
          bytes,
          commandOffset: offset,
          commandSize: commandSize,
          stringOffsetField: 8,
          minimumStringOffset: 24,
        );
        if (path != null) {
          dylibIds.add(MachODylibId(path: path));
        }
      }

      if (command == _lcRpath && commandSize >= 12) {
        final path = _readCommandString(
          bytes,
          commandOffset: offset,
          commandSize: commandSize,
          stringOffsetField: 8,
          minimumStringOffset: 12,
        );
        if (path != null) {
          rpaths.add(MachORpath(path: path));
        }
      }

      if (command == _lcSegment || command == _lcSegment64) {
        final segment = _parseSegmentCommand(
          bytes,
          offset,
          commandSize,
          is64Bit: command == _lcSegment64,
        );
        if (segment != null) {
          segments.add(segment);
        }
      }

      if (command == _lcSymtab && commandSize >= 24) {
        symbolTables.add(
          MachOSymbolTable(
            symbolOffset: _readU32(bytes, offset + 8),
            symbolCount: _readU32(bytes, offset + 12),
            stringOffset: _readU32(bytes, offset + 16),
            stringSize: _readU32(bytes, offset + 20),
          ),
        );
      }

      if (command == _lcDysymtab && commandSize >= 80) {
        dynamicSymbolTables.add(
          MachODynamicSymbolTable(
            localSymbolIndex: _readU32(bytes, offset + 8),
            localSymbolCount: _readU32(bytes, offset + 12),
            externalSymbolIndex: _readU32(bytes, offset + 16),
            externalSymbolCount: _readU32(bytes, offset + 20),
            undefinedSymbolIndex: _readU32(bytes, offset + 24),
            undefinedSymbolCount: _readU32(bytes, offset + 28),
            indirectSymbolOffset: _readU32(bytes, offset + 56),
            indirectSymbolCount: _readU32(bytes, offset + 60),
          ),
        );
      }

      if (command == _lcUuid && commandSize >= 24) {
        uuids.add(MachOUuid(value: _uuidString(bytes, offset + 8)));
      }

      if (command == _lcBuildVersion && commandSize >= 24) {
        buildVersions.add(
          MachOBuildVersion(
            platform: _readU32(bytes, offset + 8),
            minimumOsVersion: _versionString(_readU32(bytes, offset + 12)),
            sdkVersion: _versionString(_readU32(bytes, offset + 16)),
          ),
        );
      }

      final legacyPlatform = _legacyVersionPlatform(command);
      if (legacyPlatform != null && commandSize >= 16) {
        buildVersions.add(
          MachOBuildVersion(
            platform: legacyPlatform,
            minimumOsVersion: _versionString(_readU32(bytes, offset + 8)),
            sdkVersion: _versionString(_readU32(bytes, offset + 12)),
          ),
        );
      }

      if (command == _lcSourceVersion && commandSize >= 16) {
        sourceVersions.add(
          MachOSourceVersion(
            version: _sourceVersionString(_readU64(bytes, offset + 8)),
          ),
        );
      }

      if (command == _lcCodeSignature && commandSize >= 16) {
        codeSignatures.add(
          MachOCodeSignature(
            dataOffset: _readU32(bytes, offset + 8),
            dataSize: _readU32(bytes, offset + 12),
          ),
        );
      }

      offset += commandSize;
    }

    final symbols = _readSymbolsFromBytes(
      bytes,
      is64Bit: header.is64Bit,
      symbolTables: symbolTables,
    );
    final sectionStrings = _readSectionStringsFromBytes(
      bytes,
      segments: segments,
    );
    final objcSelectors = _readObjCSelectorsFromBytes(
      bytes,
      is64Bit: header.is64Bit,
      segments: segments,
    );
    final objcClasses = _readObjCClassesFromBytes(
      bytes,
      is64Bit: header.is64Bit,
      segments: segments,
    );
    final objcMethods = _readObjCMethodsFromBytes(
      bytes,
      is64Bit: header.is64Bit,
      segments: segments,
    );

    return MachOReport(
      linkedDylibs: linkedDylibs,
      architectures: architectures,
      buildVersions: buildVersions,
      rpaths: rpaths,
      dylibIds: dylibIds,
      uuids: uuids,
      sourceVersions: sourceVersions,
      codeSignatures: codeSignatures,
      segments: segments,
      symbolTables: symbolTables,
      symbols: symbols,
      sectionStrings: sectionStrings,
      dynamicSymbolTables: dynamicSymbolTables,
      objcSelectors: objcSelectors,
      objcClasses: objcClasses,
      objcMethods: objcMethods,
    );
  }
}

MachOReport _deduplicatedReport(
  List<MachODylib> dylibs, [
  List<MachOArchitecture> architectures = const [],
  List<MachOBuildVersion> buildVersions = const [],
  List<MachORpath> rpaths = const [],
  List<MachODylibId> dylibIds = const [],
  List<MachOUuid> uuids = const [],
  List<MachOSourceVersion> sourceVersions = const [],
  List<MachOCodeSignature> codeSignatures = const [],
  List<MachOSegment> segments = const [],
  List<MachOSymbolTable> symbolTables = const [],
  List<MachOSymbol> symbols = const [],
  List<MachOSectionString> sectionStrings = const [],
  List<MachODynamicSymbolTable> dynamicSymbolTables = const [],
  List<MachOObjCSelector> objcSelectors = const [],
  List<MachOObjCClass> objcClasses = const [],
  List<MachOObjCMethod> objcMethods = const [],
]) {
  final byPath = <String, MachODylib>{};
  for (final dylib in dylibs) {
    final existing = byPath[dylib.path];
    byPath[dylib.path] = existing == null
        ? dylib
        : MachODylib(path: dylib.path, weak: existing.weak && dylib.weak);
  }

  final byArchitecture = <String, MachOArchitecture>{};
  for (final architecture in architectures) {
    byArchitecture['${architecture.cpuType}|${architecture.cpuSubtype}'] =
        architecture;
  }

  final byBuildVersion = <String, MachOBuildVersion>{};
  for (final buildVersion in buildVersions) {
    byBuildVersion['${buildVersion.platform}|${buildVersion.minimumOsVersion}|${buildVersion.sdkVersion}'] =
        buildVersion;
  }

  final byRpath = <String, MachORpath>{};
  for (final rpath in rpaths) {
    byRpath[rpath.path] = rpath;
  }

  final byDylibId = <String, MachODylibId>{};
  for (final dylibId in dylibIds) {
    byDylibId[dylibId.path] = dylibId;
  }

  final byUuid = <String, MachOUuid>{};
  for (final uuid in uuids) {
    byUuid[uuid.value] = uuid;
  }

  final bySourceVersion = <String, MachOSourceVersion>{};
  for (final sourceVersion in sourceVersions) {
    bySourceVersion[sourceVersion.version] = sourceVersion;
  }

  final byCodeSignature = <String, MachOCodeSignature>{};
  for (final codeSignature in codeSignatures) {
    byCodeSignature['${codeSignature.dataOffset}|${codeSignature.dataSize}'] =
        codeSignature;
  }

  final sectionsBySegment = <String, Map<String, MachOSection>>{};
  for (final segment in segments) {
    final sections = sectionsBySegment.putIfAbsent(
      segment.name,
      () => <String, MachOSection>{},
    );
    for (final section in segment.sections) {
      sections['${section.segmentName}|${section.name}'] = section;
    }
  }

  final bySymbolTable = <String, MachOSymbolTable>{};
  for (final symbolTable in symbolTables) {
    bySymbolTable['${symbolTable.symbolOffset}|${symbolTable.symbolCount}|${symbolTable.stringOffset}|${symbolTable.stringSize}'] =
        symbolTable;
  }

  final bySymbol = <String, MachOSymbol>{};
  for (final symbol in symbols) {
    bySymbol['${symbol.name}|${symbol.type}|${symbol.sectionIndex}|${symbol.description}|${symbol.value}'] =
        symbol;
  }

  final bySectionString = <String, MachOSectionString>{};
  for (final sectionString in sectionStrings) {
    bySectionString['${sectionString.sectionName}|${sectionString.value}'] =
        sectionString;
  }

  final byDynamicSymbolTable = <String, MachODynamicSymbolTable>{};
  for (final dynamicSymbolTable in dynamicSymbolTables) {
    byDynamicSymbolTable['${dynamicSymbolTable.localSymbolIndex}|${dynamicSymbolTable.localSymbolCount}|${dynamicSymbolTable.externalSymbolIndex}|${dynamicSymbolTable.externalSymbolCount}|${dynamicSymbolTable.undefinedSymbolIndex}|${dynamicSymbolTable.undefinedSymbolCount}|${dynamicSymbolTable.indirectSymbolOffset}|${dynamicSymbolTable.indirectSymbolCount}'] =
        dynamicSymbolTable;
  }

  final byObjCSelector = <String, MachOObjCSelector>{};
  for (final objcSelector in objcSelectors) {
    byObjCSelector['${objcSelector.sourceSection}|${objcSelector.name}|${objcSelector.targetAddress}'] =
        objcSelector;
  }

  final byObjCClass = <String, MachOObjCClass>{};
  for (final objcClass in objcClasses) {
    byObjCClass['${objcClass.sourceSection}|${objcClass.name}|${objcClass.classAddress}'] =
        objcClass;
  }

  final byObjCMethod = <String, MachOObjCMethod>{};
  for (final objcMethod in objcMethods) {
    byObjCMethod['${objcMethod.className}|${objcMethod.sourceSection}|${objcMethod.name}|${objcMethod.methodListAddress}'] =
        objcMethod;
  }

  return MachOReport(
    linkedDylibs: byPath.values.toList(),
    architectures: byArchitecture.values.toList(),
    buildVersions: byBuildVersion.values.toList(),
    rpaths: byRpath.values.toList(),
    dylibIds: byDylibId.values.toList(),
    uuids: byUuid.values.toList(),
    sourceVersions: bySourceVersion.values.toList(),
    codeSignatures: byCodeSignature.values.toList(),
    segments: [
      for (final entry in sectionsBySegment.entries)
        MachOSegment(name: entry.key, sections: entry.value.values.toList()),
    ],
    symbolTables: bySymbolTable.values.toList(),
    symbols: bySymbol.values.toList(),
    sectionStrings: bySectionString.values.toList(),
    dynamicSymbolTables: byDynamicSymbolTable.values.toList(),
    objcSelectors: byObjCSelector.values.toList(),
    objcClasses: byObjCClass.values.toList(),
    objcMethods: byObjCMethod.values.toList(),
  );
}

class _MachOHeader {
  const _MachOHeader({
    required this.cpuType,
    required this.cpuSubtype,
    required this.is64Bit,
    required this.commandCount,
    required this.loadCommandsOffset,
    required this.loadCommandsEnd,
  });

  final int cpuType;
  final int cpuSubtype;
  final bool is64Bit;
  final int commandCount;
  final int loadCommandsOffset;
  final int loadCommandsEnd;
}

class _ObjCClassMetadata {
  const _ObjCClassMetadata({
    required this.name,
    required this.classRoAddress,
    required this.baseMethodsAddress,
  });

  final String name;
  final int classRoAddress;
  final int baseMethodsAddress;
}

class _ObjCMethodListLayout {
  const _ObjCMethodListLayout({
    required this.entrySize,
    required this.methodCount,
    required this.isSmall,
    required this.hasDirectSelector,
  });

  final int entrySize;
  final int methodCount;
  final bool isSmall;
  final bool hasDirectSelector;
}

_MachOHeader? _readHeader(List<int> bytes) {
  if (bytes.length < 28) return null;

  final magic = _readU32(bytes, 0);
  final is64Bit = switch (magic) {
    _mhMagic64 => true,
    _mhMagic => false,
    _ => null,
  };
  if (is64Bit == null) return null;

  final headerSize = is64Bit ? 32 : 28;
  if (bytes.length < headerSize) return null;

  return _MachOHeader(
    cpuType: _readU32(bytes, 4),
    cpuSubtype: _readU32(bytes, 8),
    is64Bit: is64Bit,
    commandCount: _readU32(bytes, 16),
    loadCommandsOffset: headerSize,
    loadCommandsEnd: _boundedEnd(headerSize, _readU32(bytes, 20), bytes.length),
  );
}

List<int> _readRange(RandomAccessFile raf, int offset, int length) {
  if (offset < 0 || length <= 0) return const [];
  raf.setPositionSync(offset);
  return raf.readSync(length);
}

bool _isDylibLoadCommand(int command) {
  return {
    _lcLoadDylib,
    _lcLoadWeakDylib,
    _lcReexportDylib,
    _lcLazyLoadDylib,
    _lcLoadUpwardDylib,
  }.contains(command);
}

int? _legacyVersionPlatform(int command) {
  return switch (command) {
    _lcVersionMinMacosx => 1,
    _lcVersionMinIphoneos => 2,
    _lcVersionMinTvos => 3,
    _lcVersionMinWatchos => 4,
    _ => null,
  };
}

String _readNullTerminatedString(List<int> bytes, int start, int end) {
  var cursor = start;
  while (cursor < end && bytes[cursor] != 0) {
    cursor += 1;
  }
  return latin1.decode(bytes.sublist(start, cursor), allowInvalid: true);
}

String? _readCommandString(
  List<int> bytes, {
  required int commandOffset,
  required int commandSize,
  required int stringOffsetField,
  required int minimumStringOffset,
}) {
  final stringOffset = _readU32(bytes, commandOffset + stringOffsetField);
  final stringStart = commandOffset + stringOffset;
  if (stringOffset < minimumStringOffset ||
      stringStart >= commandOffset + commandSize) {
    return null;
  }

  final value = _readNullTerminatedString(
    bytes,
    stringStart,
    commandOffset + commandSize,
  );
  return value.isEmpty ? null : value;
}

MachOSegment? _parseSegmentCommand(
  List<int> bytes,
  int commandOffset,
  int commandSize, {
  required bool is64Bit,
}) {
  final commandEnd = commandOffset + commandSize;
  final segmentHeaderSize = is64Bit ? 72 : 56;
  if (commandSize < segmentHeaderSize) return null;

  final segmentName = _readFixedString(bytes, commandOffset + 8, 16);
  if (segmentName.isEmpty) return null;

  final sectionCount = _readU32(bytes, commandOffset + (is64Bit ? 64 : 48));
  final sectionSize = is64Bit ? 80 : 68;
  final sectionStart = commandOffset + segmentHeaderSize;
  final sections = <MachOSection>[];

  for (var i = 0; i < sectionCount; i += 1) {
    final offset = sectionStart + i * sectionSize;
    if (offset + 32 > commandEnd) break;

    final sectionName = _readFixedString(bytes, offset, 16);
    if (sectionName.isEmpty) continue;

    final sectionSegmentName = _readFixedString(bytes, offset + 16, 16);
    sections.add(
      MachOSection(
        segmentName: sectionSegmentName.isEmpty
            ? segmentName
            : sectionSegmentName,
        name: sectionName,
        address: is64Bit
            ? _readU64(bytes, offset + 32)
            : _readU32(bytes, offset + 32),
        size: is64Bit
            ? _readU64(bytes, offset + 40)
            : _readU32(bytes, offset + 36),
        fileOffset: _readU32(bytes, offset + (is64Bit ? 48 : 40)),
        flags: _readU32(bytes, offset + (is64Bit ? 64 : 56)),
      ),
    );
  }

  return MachOSegment(name: segmentName, sections: sections);
}

List<MachOSectionString> _readSectionStringsFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required List<MachOSegment> segments,
}) {
  final sectionStrings = <MachOSectionString>[];

  for (final section in _stringSections(segments)) {
    if (!_canReadSection(section, availableLength)) continue;

    sectionStrings.addAll(
      _parseSectionStrings(
        section,
        _readRange(raf, fileOffset + section.fileOffset, section.size),
      ),
    );
  }

  return sectionStrings;
}

List<MachOObjCSelector> _readObjCSelectorsFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required bool is64Bit,
  required List<MachOSegment> segments,
}) {
  final selectors = <MachOObjCSelector>[];
  final pointerSize = is64Bit ? 8 : 4;
  final stringSections = _stringSections(segments).toList();

  for (final section in _sectionsNamed(segments, '__objc_selrefs')) {
    if (!_canReadSection(section, availableLength)) continue;

    final sectionBytes = _readRange(
      raf,
      fileOffset + section.fileOffset,
      section.size,
    );
    for (
      var offset = 0;
      offset + pointerSize <= sectionBytes.length;
      offset += pointerSize
    ) {
      final targetAddress = is64Bit
          ? _readU64(sectionBytes, offset)
          : _readU32(sectionBytes, offset);
      final name = _readCStringAtAddressFromFile(
        raf,
        fileOffset,
        availableLength,
        stringSections,
        targetAddress,
      );
      if (name == null) continue;

      selectors.add(
        MachOObjCSelector(
          name: name,
          sourceSection: section.displayName,
          targetAddress: targetAddress,
        ),
      );
    }
  }

  return selectors;
}

List<MachOObjCClass> _readObjCClassesFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required bool is64Bit,
  required List<MachOSegment> segments,
}) {
  final classes = <MachOObjCClass>[];
  final pointerSize = is64Bit ? 8 : 4;
  final allSections = _allSections(segments).toList();
  final stringSections = _stringSections(segments).toList();

  for (final section in _objcClassReferenceSections(segments)) {
    if (!_canReadSection(section, availableLength)) continue;

    final sectionBytes = _readRange(
      raf,
      fileOffset + section.fileOffset,
      section.size,
    );
    for (
      var offset = 0;
      offset + pointerSize <= sectionBytes.length;
      offset += pointerSize
    ) {
      final classAddress = is64Bit
          ? _readU64(sectionBytes, offset)
          : _readU32(sectionBytes, offset);
      final name = _readObjCClassNameFromFile(
        raf,
        fileOffset,
        availableLength,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        classAddress: classAddress,
      );
      if (name == null) continue;

      classes.add(
        MachOObjCClass(
          name: name,
          sourceSection: section.displayName,
          classAddress: classAddress,
        ),
      );
    }
  }

  return classes;
}

List<MachOObjCMethod> _readObjCMethodsFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required bool is64Bit,
  required List<MachOSegment> segments,
}) {
  final methods = <MachOObjCMethod>[];
  final pointerSize = is64Bit ? 8 : 4;
  final allSections = _allSections(segments).toList();
  final stringSections = _stringSections(segments).toList();

  for (final section in _objcClassReferenceSections(segments)) {
    if (!_canReadSection(section, availableLength)) continue;

    final sectionBytes = _readRange(
      raf,
      fileOffset + section.fileOffset,
      section.size,
    );
    for (
      var offset = 0;
      offset + pointerSize <= sectionBytes.length;
      offset += pointerSize
    ) {
      final classAddress = is64Bit
          ? _readU64(sectionBytes, offset)
          : _readU32(sectionBytes, offset);
      final metadata = _readObjCClassMetadataFromFile(
        raf,
        fileOffset,
        availableLength,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        classAddress: classAddress,
      );
      if (metadata == null || metadata.baseMethodsAddress == 0) continue;

      methods.addAll(
        _readObjCMethodListFromFile(
          raf,
          fileOffset,
          availableLength,
          is64Bit: is64Bit,
          allSections: allSections,
          stringSections: stringSections,
          className: metadata.name,
          methodListAddress: metadata.baseMethodsAddress,
        ),
      );
    }
  }

  return methods;
}

List<MachOSectionString> _readSectionStringsFromBytes(
  List<int> bytes, {
  required List<MachOSegment> segments,
}) {
  final sectionStrings = <MachOSectionString>[];

  for (final section in _stringSections(segments)) {
    if (!_canReadSection(section, bytes.length)) continue;

    sectionStrings.addAll(
      _parseSectionStrings(
        section,
        bytes.sublist(section.fileOffset, section.fileOffset + section.size),
      ),
    );
  }

  return sectionStrings;
}

List<MachOObjCMethod> _readObjCMethodsFromBytes(
  List<int> bytes, {
  required bool is64Bit,
  required List<MachOSegment> segments,
}) {
  final methods = <MachOObjCMethod>[];
  final pointerSize = is64Bit ? 8 : 4;
  final allSections = _allSections(segments).toList();
  final stringSections = _stringSections(segments).toList();

  for (final section in _objcClassReferenceSections(segments)) {
    if (!_canReadSection(section, bytes.length)) continue;

    final sectionBytes = bytes.sublist(
      section.fileOffset,
      section.fileOffset + section.size,
    );
    for (
      var offset = 0;
      offset + pointerSize <= sectionBytes.length;
      offset += pointerSize
    ) {
      final classAddress = is64Bit
          ? _readU64(sectionBytes, offset)
          : _readU32(sectionBytes, offset);
      final metadata = _readObjCClassMetadataFromBytes(
        bytes,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        classAddress: classAddress,
      );
      if (metadata == null || metadata.baseMethodsAddress == 0) continue;

      methods.addAll(
        _readObjCMethodListFromBytes(
          bytes,
          is64Bit: is64Bit,
          allSections: allSections,
          stringSections: stringSections,
          className: metadata.name,
          methodListAddress: metadata.baseMethodsAddress,
        ),
      );
    }
  }

  return methods;
}

List<MachOObjCClass> _readObjCClassesFromBytes(
  List<int> bytes, {
  required bool is64Bit,
  required List<MachOSegment> segments,
}) {
  final classes = <MachOObjCClass>[];
  final pointerSize = is64Bit ? 8 : 4;
  final allSections = _allSections(segments).toList();
  final stringSections = _stringSections(segments).toList();

  for (final section in _objcClassReferenceSections(segments)) {
    if (!_canReadSection(section, bytes.length)) continue;

    final sectionBytes = bytes.sublist(
      section.fileOffset,
      section.fileOffset + section.size,
    );
    for (
      var offset = 0;
      offset + pointerSize <= sectionBytes.length;
      offset += pointerSize
    ) {
      final classAddress = is64Bit
          ? _readU64(sectionBytes, offset)
          : _readU32(sectionBytes, offset);
      final name = _readObjCClassNameFromBytes(
        bytes,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        classAddress: classAddress,
      );
      if (name == null) continue;

      classes.add(
        MachOObjCClass(
          name: name,
          sourceSection: section.displayName,
          classAddress: classAddress,
        ),
      );
    }
  }

  return classes;
}

List<MachOObjCSelector> _readObjCSelectorsFromBytes(
  List<int> bytes, {
  required bool is64Bit,
  required List<MachOSegment> segments,
}) {
  final selectors = <MachOObjCSelector>[];
  final pointerSize = is64Bit ? 8 : 4;
  final stringSections = _stringSections(segments).toList();

  for (final section in _sectionsNamed(segments, '__objc_selrefs')) {
    if (!_canReadSection(section, bytes.length)) continue;

    final sectionBytes = bytes.sublist(
      section.fileOffset,
      section.fileOffset + section.size,
    );
    for (
      var offset = 0;
      offset + pointerSize <= sectionBytes.length;
      offset += pointerSize
    ) {
      final targetAddress = is64Bit
          ? _readU64(sectionBytes, offset)
          : _readU32(sectionBytes, offset);
      final name = _readCStringAtAddressFromBytes(
        bytes,
        stringSections,
        targetAddress,
      );
      if (name == null) continue;

      selectors.add(
        MachOObjCSelector(
          name: name,
          sourceSection: section.displayName,
          targetAddress: targetAddress,
        ),
      );
    }
  }

  return selectors;
}

String? _readObjCClassNameFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required int classAddress,
}) {
  return _readObjCClassMetadataFromFile(
    raf,
    fileOffset,
    availableLength,
    is64Bit: is64Bit,
    allSections: allSections,
    stringSections: stringSections,
    classAddress: classAddress,
  )?.name;
}

_ObjCClassMetadata? _readObjCClassMetadataFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required int classAddress,
}) {
  final classDataAddress = _readPointerAtAddressFromFile(
    raf,
    fileOffset,
    availableLength,
    allSections,
    classAddress + (is64Bit ? 32 : 16),
    is64Bit: is64Bit,
  );
  if (classDataAddress == null) return null;

  final classRoAddress = classDataAddress & (is64Bit ? ~0x7 : ~0x3);
  final nameAddress = _readPointerAtAddressFromFile(
    raf,
    fileOffset,
    availableLength,
    allSections,
    classRoAddress + (is64Bit ? 24 : 16),
    is64Bit: is64Bit,
  );
  if (nameAddress == null) return null;

  final name = _readCStringAtAddressFromFile(
    raf,
    fileOffset,
    availableLength,
    stringSections,
    nameAddress,
  );
  if (name == null) return null;

  final baseMethodsAddress =
      _readPointerAtAddressFromFile(
        raf,
        fileOffset,
        availableLength,
        allSections,
        classRoAddress + (is64Bit ? 32 : 20),
        is64Bit: is64Bit,
      ) ??
      0;

  return _ObjCClassMetadata(
    name: name,
    classRoAddress: classRoAddress,
    baseMethodsAddress: baseMethodsAddress,
  );
}

String? _readObjCClassNameFromBytes(
  List<int> bytes, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required int classAddress,
}) {
  return _readObjCClassMetadataFromBytes(
    bytes,
    is64Bit: is64Bit,
    allSections: allSections,
    stringSections: stringSections,
    classAddress: classAddress,
  )?.name;
}

_ObjCClassMetadata? _readObjCClassMetadataFromBytes(
  List<int> bytes, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required int classAddress,
}) {
  final classDataAddress = _readPointerAtAddressFromBytes(
    bytes,
    allSections,
    classAddress + (is64Bit ? 32 : 16),
    is64Bit: is64Bit,
  );
  if (classDataAddress == null) return null;

  final classRoAddress = classDataAddress & (is64Bit ? ~0x7 : ~0x3);
  final nameAddress = _readPointerAtAddressFromBytes(
    bytes,
    allSections,
    classRoAddress + (is64Bit ? 24 : 16),
    is64Bit: is64Bit,
  );
  if (nameAddress == null) return null;

  final name = _readCStringAtAddressFromBytes(
    bytes,
    stringSections,
    nameAddress,
  );
  if (name == null) return null;

  final baseMethodsAddress =
      _readPointerAtAddressFromBytes(
        bytes,
        allSections,
        classRoAddress + (is64Bit ? 32 : 20),
        is64Bit: is64Bit,
      ) ??
      0;

  return _ObjCClassMetadata(
    name: name,
    classRoAddress: classRoAddress,
    baseMethodsAddress: baseMethodsAddress,
  );
}

List<MachOObjCMethod> _readObjCMethodListFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required String className,
  required int methodListAddress,
}) {
  final section = _sectionContainingAddress(allSections, methodListAddress);
  if (section == null || !_canReadSection(section, availableLength)) {
    return const [];
  }

  final header = _readBytesAtAddressFromFile(
    raf,
    fileOffset,
    availableLength,
    allSections,
    methodListAddress,
    8,
  );
  if (header == null) return const [];
  final layout = _objcMethodListLayout(
    _readU32(header, 0),
    _readU32(header, 4),
    is64Bit: is64Bit,
  );
  if (layout == null) return const [];

  return _readObjCMethodListEntriesFromFile(
    raf,
    fileOffset,
    availableLength,
    is64Bit: is64Bit,
    allSections: allSections,
    stringSections: stringSections,
    className: className,
    sourceSection: section.displayName,
    methodListAddress: methodListAddress,
    layout: layout,
  );
}

List<MachOObjCMethod> _readObjCMethodListFromBytes(
  List<int> bytes, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required String className,
  required int methodListAddress,
}) {
  final section = _sectionContainingAddress(allSections, methodListAddress);
  if (section == null || !_canReadSection(section, bytes.length)) {
    return const [];
  }

  final header = _readBytesAtAddressFromBytes(
    bytes,
    allSections,
    methodListAddress,
    8,
  );
  if (header == null) return const [];
  final layout = _objcMethodListLayout(
    _readU32(header, 0),
    _readU32(header, 4),
    is64Bit: is64Bit,
  );
  if (layout == null) return const [];

  return _readObjCMethodListEntriesFromBytes(
    bytes,
    is64Bit: is64Bit,
    allSections: allSections,
    stringSections: stringSections,
    className: className,
    sourceSection: section.displayName,
    methodListAddress: methodListAddress,
    layout: layout,
  );
}

List<MachOObjCMethod> _readObjCMethodListEntriesFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required String className,
  required String sourceSection,
  required int methodListAddress,
  required _ObjCMethodListLayout layout,
}) {
  final methods = <MachOObjCMethod>[];

  for (var i = 0; i < layout.methodCount; i += 1) {
    final entryAddress = methodListAddress + 8 + i * layout.entrySize;
    final nameAddress = layout.isSmall
        ? _readSmallObjCMethodNameAddressFromFile(
            raf,
            fileOffset,
            availableLength,
            allSections,
            entryAddress,
            hasDirectSelector: layout.hasDirectSelector,
            is64Bit: is64Bit,
          )
        : _readPointerAtAddressFromFile(
            raf,
            fileOffset,
            availableLength,
            allSections,
            entryAddress,
            is64Bit: is64Bit,
          );
    if (nameAddress == null) continue;

    final name = _readCStringAtAddressFromFile(
      raf,
      fileOffset,
      availableLength,
      stringSections,
      nameAddress,
    );
    if (name == null) continue;

    methods.add(
      MachOObjCMethod(
        name: name,
        className: className,
        sourceSection: sourceSection,
        methodListAddress: methodListAddress,
      ),
    );
  }

  return methods;
}

List<MachOObjCMethod> _readObjCMethodListEntriesFromBytes(
  List<int> bytes, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required String className,
  required String sourceSection,
  required int methodListAddress,
  required _ObjCMethodListLayout layout,
}) {
  final methods = <MachOObjCMethod>[];

  for (var i = 0; i < layout.methodCount; i += 1) {
    final entryAddress = methodListAddress + 8 + i * layout.entrySize;
    final nameAddress = layout.isSmall
        ? _readSmallObjCMethodNameAddressFromBytes(
            bytes,
            allSections,
            entryAddress,
            hasDirectSelector: layout.hasDirectSelector,
            is64Bit: is64Bit,
          )
        : _readPointerAtAddressFromBytes(
            bytes,
            allSections,
            entryAddress,
            is64Bit: is64Bit,
          );
    if (nameAddress == null) continue;

    final name = _readCStringAtAddressFromBytes(
      bytes,
      stringSections,
      nameAddress,
    );
    if (name == null) continue;

    methods.add(
      MachOObjCMethod(
        name: name,
        className: className,
        sourceSection: sourceSection,
        methodListAddress: methodListAddress,
      ),
    );
  }

  return methods;
}

int? _readSmallObjCMethodNameAddressFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength,
  List<MachOSection> allSections,
  int entryAddress, {
  required bool hasDirectSelector,
  required bool is64Bit,
}) {
  final entry = _readBytesAtAddressFromFile(
    raf,
    fileOffset,
    availableLength,
    allSections,
    entryAddress,
    12,
  );
  if (entry == null) return null;

  final nameReferenceAddress = entryAddress + _readI32(entry, 0);
  if (hasDirectSelector) return nameReferenceAddress;

  return _readPointerAtAddressFromFile(
    raf,
    fileOffset,
    availableLength,
    allSections,
    nameReferenceAddress,
    is64Bit: is64Bit,
  );
}

int? _readSmallObjCMethodNameAddressFromBytes(
  List<int> bytes,
  List<MachOSection> allSections,
  int entryAddress, {
  required bool hasDirectSelector,
  required bool is64Bit,
}) {
  final entry = _readBytesAtAddressFromBytes(
    bytes,
    allSections,
    entryAddress,
    12,
  );
  if (entry == null) return null;

  final nameReferenceAddress = entryAddress + _readI32(entry, 0);
  if (hasDirectSelector) return nameReferenceAddress;

  return _readPointerAtAddressFromBytes(
    bytes,
    allSections,
    nameReferenceAddress,
    is64Bit: is64Bit,
  );
}

Iterable<MachOSection> _stringSections(List<MachOSegment> segments) sync* {
  for (final segment in segments) {
    for (final section in segment.sections) {
      if (_isCStringSection(section)) yield section;
    }
  }
}

Iterable<MachOSection> _allSections(List<MachOSegment> segments) sync* {
  for (final segment in segments) {
    yield* segment.sections;
  }
}

Iterable<MachOSection> _objcClassReferenceSections(
  List<MachOSegment> segments,
) sync* {
  for (final section in _allSections(segments)) {
    if (section.name == '__objc_classrefs' ||
        section.name == '__objc_classlist') {
      yield section;
    }
  }
}

Iterable<MachOSection> _sectionsNamed(
  List<MachOSegment> segments,
  String name,
) sync* {
  for (final segment in segments) {
    for (final section in segment.sections) {
      if (section.name == name) yield section;
    }
  }
}

bool _canReadSection(MachOSection section, int availableLength) {
  return section.size > 0 &&
      section.size <= _maxSectionStringBytes &&
      _rangeWithin(section.fileOffset, section.size, availableLength);
}

bool _isCStringSection(MachOSection section) {
  return {
    '__cstring',
    '__objc_methname',
    '__objc_classname',
    '__objc_methtype',
  }.contains(section.name);
}

List<MachOSectionString> _parseSectionStrings(
  MachOSection section,
  List<int> bytes,
) {
  final values = <MachOSectionString>[];
  var start = 0;

  for (var cursor = 0; cursor <= bytes.length; cursor += 1) {
    if (cursor < bytes.length && bytes[cursor] != 0) continue;
    if (cursor > start) {
      values.add(
        MachOSectionString(
          sectionName: section.displayName,
          value: latin1.decode(
            bytes.sublist(start, cursor),
            allowInvalid: true,
          ),
        ),
      );
    }
    start = cursor + 1;
  }

  return values;
}

String? _readCStringAtAddressFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength,
  List<MachOSection> stringSections,
  int address,
) {
  final section = _sectionContainingAddress(stringSections, address);
  if (section == null || !_canReadSection(section, availableLength)) {
    return null;
  }

  final stringOffset = section.fileOffset + (address - section.address);
  if (!_rangeWithin(stringOffset, 1, availableLength)) return null;

  final bytes = _readRange(
    raf,
    fileOffset + stringOffset,
    section.fileOffset + section.size - stringOffset,
  );
  if (bytes.isEmpty) return null;

  final value = _readNullTerminatedString(bytes, 0, bytes.length);
  return value.isEmpty ? null : value;
}

String? _readCStringAtAddressFromBytes(
  List<int> bytes,
  List<MachOSection> stringSections,
  int address,
) {
  final section = _sectionContainingAddress(stringSections, address);
  if (section == null || !_canReadSection(section, bytes.length)) {
    return null;
  }

  final stringOffset = section.fileOffset + (address - section.address);
  if (!_rangeWithin(stringOffset, 1, bytes.length)) return null;

  final value = _readNullTerminatedString(
    bytes,
    stringOffset,
    section.fileOffset + section.size,
  );
  return value.isEmpty ? null : value;
}

MachOSection? _sectionContainingAddress(
  List<MachOSection> sections,
  int address,
) {
  for (final section in sections) {
    if (section.address <= 0 || section.size <= 0) continue;
    final end = section.address + section.size;
    if (address >= section.address && address < end) {
      return section;
    }
  }
  return null;
}

int? _readPointerAtAddressFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength,
  List<MachOSection> sections,
  int address, {
  required bool is64Bit,
}) {
  final section = _sectionContainingAddress(sections, address);
  if (section == null || !_canReadSection(section, availableLength)) {
    return null;
  }

  final pointerSize = is64Bit ? 8 : 4;
  final pointerOffset = section.fileOffset + (address - section.address);
  if (!_rangeWithin(pointerOffset, pointerSize, availableLength)) return null;

  final bytes = _readRange(raf, fileOffset + pointerOffset, pointerSize);
  return is64Bit ? _readU64(bytes, 0) : _readU32(bytes, 0);
}

List<int>? _readBytesAtAddressFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength,
  List<MachOSection> sections,
  int address,
  int length,
) {
  final section = _sectionContainingAddress(sections, address);
  if (section == null || !_canReadSection(section, availableLength)) {
    return null;
  }

  final dataOffset = section.fileOffset + (address - section.address);
  if (!_rangeWithin(dataOffset, length, availableLength)) return null;

  return _readRange(raf, fileOffset + dataOffset, length);
}

int? _readPointerAtAddressFromBytes(
  List<int> bytes,
  List<MachOSection> sections,
  int address, {
  required bool is64Bit,
}) {
  final section = _sectionContainingAddress(sections, address);
  if (section == null || !_canReadSection(section, bytes.length)) {
    return null;
  }

  final pointerSize = is64Bit ? 8 : 4;
  final pointerOffset = section.fileOffset + (address - section.address);
  if (!_rangeWithin(pointerOffset, pointerSize, bytes.length)) return null;

  return is64Bit
      ? _readU64(bytes, pointerOffset)
      : _readU32(bytes, pointerOffset);
}

List<int>? _readBytesAtAddressFromBytes(
  List<int> bytes,
  List<MachOSection> sections,
  int address,
  int length,
) {
  final section = _sectionContainingAddress(sections, address);
  if (section == null || !_canReadSection(section, bytes.length)) {
    return null;
  }

  final dataOffset = section.fileOffset + (address - section.address);
  if (!_rangeWithin(dataOffset, length, bytes.length)) return null;

  return bytes.sublist(dataOffset, dataOffset + length);
}

_ObjCMethodListLayout? _objcMethodListLayout(
  int entsizeAndFlags,
  int methodCount, {
  required bool is64Bit,
}) {
  final isSmall = (entsizeAndFlags & _objcSmallMethodListFlag) != 0;
  final hasDirectSelector =
      (entsizeAndFlags & _objcDirectSelectorMethodListFlag) != 0;
  final entrySize = _methodListEntrySize(
    entsizeAndFlags,
    is64Bit: is64Bit,
    isSmall: isSmall,
  );
  if (!_canReadMethodList(
    entrySize,
    methodCount,
    is64Bit: is64Bit,
    isSmall: isSmall,
  )) {
    return null;
  }

  return _ObjCMethodListLayout(
    entrySize: entrySize,
    methodCount: methodCount,
    isSmall: isSmall,
    hasDirectSelector: hasDirectSelector,
  );
}

int _methodListEntrySize(
  int entsizeAndFlags, {
  required bool is64Bit,
  required bool isSmall,
}) {
  final entrySize = entsizeAndFlags & 0xfffc;
  final minimumEntrySize = isSmall ? 12 : (is64Bit ? 24 : 12);
  return entrySize < minimumEntrySize ? minimumEntrySize : entrySize;
}

bool _canReadMethodList(
  int entrySize,
  int methodCount, {
  required bool is64Bit,
  required bool isSmall,
}) {
  final minimumEntrySize = isSmall ? 12 : (is64Bit ? 24 : 12);
  if (entrySize < minimumEntrySize ||
      methodCount <= 0 ||
      methodCount > _maxObjCMethodCount) {
    return false;
  }

  final byteLength = entrySize * methodCount;
  return byteLength > 0 && byteLength <= _maxObjCMethodListBytes;
}

List<MachOSymbol> _readSymbolsFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required bool is64Bit,
  required List<MachOSymbolTable> symbolTables,
}) {
  final symbols = <MachOSymbol>[];
  final entrySize = is64Bit ? 16 : 12;

  for (final symbolTable in symbolTables) {
    final symbolBytesLength = symbolTable.symbolCount * entrySize;
    if (!_canReadSymbolTable(symbolTable, symbolBytesLength, availableLength)) {
      continue;
    }

    final symbolBytes = _readRange(
      raf,
      fileOffset + symbolTable.symbolOffset,
      symbolBytesLength,
    );
    final stringBytes = _readRange(
      raf,
      fileOffset + symbolTable.stringOffset,
      symbolTable.stringSize,
    );
    symbols.addAll(
      _parseSymbolEntries(
        symbolBytes,
        stringBytes,
        is64Bit: is64Bit,
        symbolCount: symbolTable.symbolCount,
      ),
    );
  }

  return symbols;
}

List<MachOSymbol> _readSymbolsFromBytes(
  List<int> bytes, {
  required bool is64Bit,
  required List<MachOSymbolTable> symbolTables,
}) {
  final symbols = <MachOSymbol>[];
  final entrySize = is64Bit ? 16 : 12;

  for (final symbolTable in symbolTables) {
    final symbolBytesLength = symbolTable.symbolCount * entrySize;
    if (!_canReadSymbolTable(symbolTable, symbolBytesLength, bytes.length)) {
      continue;
    }

    symbols.addAll(
      _parseSymbolEntries(
        bytes.sublist(
          symbolTable.symbolOffset,
          symbolTable.symbolOffset + symbolBytesLength,
        ),
        bytes.sublist(
          symbolTable.stringOffset,
          symbolTable.stringOffset + symbolTable.stringSize,
        ),
        is64Bit: is64Bit,
        symbolCount: symbolTable.symbolCount,
      ),
    );
  }

  return symbols;
}

bool _canReadSymbolTable(
  MachOSymbolTable symbolTable,
  int symbolBytesLength,
  int availableLength,
) {
  if (symbolTable.symbolCount <= 0 ||
      symbolTable.symbolOffset < 0 ||
      symbolTable.stringOffset < 0 ||
      symbolTable.stringSize <= 0 ||
      symbolBytesLength <= 0 ||
      symbolBytesLength > _maxSymbolTableBytes ||
      symbolTable.stringSize > _maxStringTableBytes) {
    return false;
  }

  return _rangeWithin(
        symbolTable.symbolOffset,
        symbolBytesLength,
        availableLength,
      ) &&
      _rangeWithin(
        symbolTable.stringOffset,
        symbolTable.stringSize,
        availableLength,
      );
}

List<MachOSymbol> _parseSymbolEntries(
  List<int> symbolBytes,
  List<int> stringBytes, {
  required bool is64Bit,
  required int symbolCount,
}) {
  final symbols = <MachOSymbol>[];
  final entrySize = is64Bit ? 16 : 12;

  for (var i = 0; i < symbolCount; i += 1) {
    final offset = i * entrySize;
    if (offset + entrySize > symbolBytes.length) break;

    final name = _readStringTableString(
      stringBytes,
      _readU32(symbolBytes, offset),
    );
    if (name == null) continue;

    symbols.add(
      MachOSymbol(
        name: name,
        type: symbolBytes[offset + 4],
        sectionIndex: symbolBytes[offset + 5],
        description: _readU16(symbolBytes, offset + 6),
        value: is64Bit
            ? _readU64(symbolBytes, offset + 8)
            : _readU32(symbolBytes, offset + 8),
      ),
    );
  }

  return symbols;
}

bool _rangeWithin(int offset, int length, int availableLength) {
  if (offset < 0 || length < 0 || availableLength < 0) return false;
  final end = offset + length;
  return end >= offset && end <= availableLength;
}

String _readFixedString(List<int> bytes, int start, int length) {
  if (start < 0 || start >= bytes.length || length <= 0) return '';

  final end = start + length > bytes.length ? bytes.length : start + length;
  var cursor = start;
  while (cursor < end && bytes[cursor] != 0) {
    cursor += 1;
  }
  return latin1.decode(bytes.sublist(start, cursor), allowInvalid: true);
}

String? _readStringTableString(List<int> bytes, int start) {
  if (start <= 0 || start >= bytes.length) return null;
  final value = _readNullTerminatedString(bytes, start, bytes.length);
  return value.isEmpty ? null : value;
}

int _readU16(List<int> bytes, int offset) {
  if (offset + 2 > bytes.length) return 0;
  return bytes[offset] | (bytes[offset + 1] << 8);
}

int _readU32(List<int> bytes, int offset) {
  if (offset + 4 > bytes.length) return 0;
  return bytes[offset] |
      (bytes[offset + 1] << 8) |
      (bytes[offset + 2] << 16) |
      (bytes[offset + 3] << 24);
}

int _readI32(List<int> bytes, int offset) {
  final value = _readU32(bytes, offset);
  return (value & 0x80000000) == 0 ? value : value - 0x100000000;
}

int _readU64(List<int> bytes, int offset) {
  if (offset + 8 > bytes.length) return 0;
  return bytes[offset] |
      (bytes[offset + 1] << 8) |
      (bytes[offset + 2] << 16) |
      (bytes[offset + 3] << 24) |
      (bytes[offset + 4] << 32) |
      (bytes[offset + 5] << 40) |
      (bytes[offset + 6] << 48) |
      (bytes[offset + 7] << 56);
}

int _readU32be(List<int> bytes, int offset) {
  if (offset + 4 > bytes.length) return 0;
  return (bytes[offset] << 24) |
      (bytes[offset + 1] << 16) |
      (bytes[offset + 2] << 8) |
      bytes[offset + 3];
}

int _readU64be(List<int> bytes, int offset) {
  if (offset + 8 > bytes.length) return 0;
  return (bytes[offset] << 56) |
      (bytes[offset + 1] << 48) |
      (bytes[offset + 2] << 40) |
      (bytes[offset + 3] << 32) |
      (bytes[offset + 4] << 24) |
      (bytes[offset + 5] << 16) |
      (bytes[offset + 6] << 8) |
      bytes[offset + 7];
}

int _boundedEnd(int start, int length, int fileLength) {
  final end = start + length;
  if (end < start) return start;
  return end > fileLength ? fileLength : end;
}

String _versionString(int version) {
  final major = (version >> 16) & 0xffff;
  final minor = (version >> 8) & 0xff;
  final patch = version & 0xff;
  return '$major.$minor.$patch';
}

String _uuidString(List<int> bytes, int offset) {
  if (offset + 16 > bytes.length) return '';
  final hex = bytes
      .sublist(offset, offset + 16)
      .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
      .join();
  return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}';
}

String _sourceVersionString(int version) {
  final a = (version >> 40) & 0xffffff;
  final b = (version >> 30) & 0x3ff;
  final c = (version >> 20) & 0x3ff;
  final d = (version >> 10) & 0x3ff;
  final e = version & 0x3ff;
  return '$a.$b.$c.$d.$e';
}

const _fatMagic = 0xcafebabe;
const _fatMagic64 = 0xcafebabf;
const _maxFatArchTableBytes = 64 * 1024;
const _maxLoadCommandBytes = 8 * 1024 * 1024;
const _objcDirectSelectorMethodListFlag = 0x40000000;
const _objcSmallMethodListFlag = 0x80000000;
const _maxObjCMethodCount = 8192;
const _maxObjCMethodListBytes = 2 * 1024 * 1024;
const _maxSectionStringBytes = 4 * 1024 * 1024;
const _maxStringTableBytes = 16 * 1024 * 1024;
const _maxSymbolTableBytes = 16 * 1024 * 1024;
const _mhMagic = 0xfeedface;
const _mhMagic64 = 0xfeedfacf;
const _lcSegment = 0x01;
const _lcSymtab = 0x02;
const _lcDysymtab = 0x0b;
const _lcLoadDylib = 0x0c;
const _lcIdDylib = 0x0d;
const _lcSegment64 = 0x19;
const _lcLoadWeakDylib = 0x80000018;
const _lcUuid = 0x1b;
const _lcRpath = 0x8000001c;
const _lcCodeSignature = 0x1d;
const _lcReexportDylib = 0x8000001f;
const _lcLazyLoadDylib = 0x20;
const _lcLoadUpwardDylib = 0x80000023;
const _lcSourceVersion = 0x2a;
const _lcBuildVersion = 0x32;
const _lcVersionMinMacosx = 0x24;
const _lcVersionMinIphoneos = 0x25;
const _lcVersionMinTvos = 0x2f;
const _lcVersionMinWatchos = 0x30;
