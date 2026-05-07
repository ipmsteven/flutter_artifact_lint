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
    this.encryptionInfos = const [],
    this.segments = const [],
    this.symbolTables = const [],
    this.symbols = const [],
    this.sectionStrings = const [],
    this.swiftTypes = const [],
    this.swiftProtocols = const [],
    this.swiftProtocolConformances = const [],
    this.swiftFields = const [],
    this.dynamicSymbolTables = const [],
    this.dyldInfos = const [],
    this.chainedFixups = const [],
    this.dyldExportsTries = const [],
    this.dyldBindSymbols = const [],
    this.dyldExportSymbols = const [],
    this.objcSelectors = const [],
    this.objcClasses = const [],
    this.objcProtocols = const [],
    this.objcMethods = const [],
    this.objcIvars = const [],
    this.objcProperties = const [],
  });

  final List<MachODylib> linkedDylibs;
  final List<MachOArchitecture> architectures;
  final List<MachOBuildVersion> buildVersions;
  final List<MachORpath> rpaths;
  final List<MachODylibId> dylibIds;
  final List<MachOUuid> uuids;
  final List<MachOSourceVersion> sourceVersions;
  final List<MachOCodeSignature> codeSignatures;
  final List<MachOEncryptionInfo> encryptionInfos;
  final List<MachOSegment> segments;
  final List<MachOSymbolTable> symbolTables;
  final List<MachOSymbol> symbols;
  final List<MachOSectionString> sectionStrings;
  final List<MachOSwiftType> swiftTypes;
  final List<MachOSwiftProtocol> swiftProtocols;
  final List<MachOSwiftProtocolConformance> swiftProtocolConformances;
  final List<MachOSwiftField> swiftFields;
  final List<MachODynamicSymbolTable> dynamicSymbolTables;
  final List<MachODyldInfo> dyldInfos;
  final List<MachOChainedFixups> chainedFixups;
  final List<MachODyldExportsTrie> dyldExportsTries;
  final List<MachODyldBindSymbol> dyldBindSymbols;
  final List<MachODyldExportSymbol> dyldExportSymbols;
  final List<MachOObjCSelector> objcSelectors;
  final List<MachOObjCClass> objcClasses;
  final List<MachOObjCProtocol> objcProtocols;
  final List<MachOObjCMethod> objcMethods;
  final List<MachOObjCIvar> objcIvars;
  final List<MachOObjCProperty> objcProperties;
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

class MachOEncryptionInfo {
  const MachOEncryptionInfo({
    required this.cryptOffset,
    required this.cryptSize,
    required this.cryptId,
  });

  final int cryptOffset;
  final int cryptSize;
  final int cryptId;

  bool get encrypted => cryptId != 0;
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

class MachOSwiftType {
  const MachOSwiftType({
    required this.name,
    required this.sourceSection,
    required this.descriptorAddress,
  });

  final String name;
  final String sourceSection;
  final int descriptorAddress;
}

class MachOSwiftProtocol {
  const MachOSwiftProtocol({
    required this.name,
    required this.sourceSection,
    required this.descriptorAddress,
  });

  final String name;
  final String sourceSection;
  final int descriptorAddress;
}

class MachOSwiftProtocolConformance {
  const MachOSwiftProtocolConformance({
    required this.typeName,
    required this.protocolName,
    required this.sourceSection,
    required this.descriptorAddress,
  });

  final String typeName;
  final String protocolName;
  final String sourceSection;
  final int descriptorAddress;
}

class MachOSwiftField {
  const MachOSwiftField({
    required this.name,
    required this.ownerTypeName,
    required this.fieldTypeName,
    required this.sourceSection,
    required this.descriptorAddress,
  });

  final String name;
  final String? ownerTypeName;
  final String? fieldTypeName;
  final String sourceSection;
  final int descriptorAddress;
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

class MachOObjCProtocol {
  const MachOObjCProtocol({
    required this.name,
    required this.sourceSection,
    required this.protocolAddress,
  });

  final String name;
  final String sourceSection;
  final int protocolAddress;
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

class MachOObjCIvar {
  const MachOObjCIvar({
    required this.name,
    required this.typeEncoding,
    required this.className,
    required this.sourceSection,
    required this.ivarListAddress,
  });

  final String name;
  final String typeEncoding;
  final String className;
  final String sourceSection;
  final int ivarListAddress;
}

class MachOObjCProperty {
  const MachOObjCProperty({
    required this.name,
    required this.attributes,
    required this.className,
    required this.sourceSection,
    required this.propertyListAddress,
  });

  final String name;
  final String attributes;
  final String className;
  final String sourceSection;
  final int propertyListAddress;
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

class MachODyldInfo {
  const MachODyldInfo({
    required this.bindOffset,
    required this.bindSize,
    required this.weakBindOffset,
    required this.weakBindSize,
    required this.lazyBindOffset,
    required this.lazyBindSize,
    required this.exportOffset,
    required this.exportSize,
  });

  final int bindOffset;
  final int bindSize;
  final int weakBindOffset;
  final int weakBindSize;
  final int lazyBindOffset;
  final int lazyBindSize;
  final int exportOffset;
  final int exportSize;
}

class MachOChainedFixups {
  const MachOChainedFixups({required this.dataOffset, required this.dataSize});

  final int dataOffset;
  final int dataSize;
}

class MachODyldExportsTrie {
  const MachODyldExportsTrie({
    required this.dataOffset,
    required this.dataSize,
  });

  final int dataOffset;
  final int dataSize;
}

class MachODyldBindSymbol {
  const MachODyldBindSymbol({required this.name, required this.source});

  final String name;
  final String source;
}

class MachODyldExportSymbol {
  const MachODyldExportSymbol({required this.name, required this.source});

  final String name;
  final String source;
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
      thinReport.encryptionInfos,
      thinReport.segments,
      thinReport.symbolTables,
      thinReport.symbols,
      thinReport.sectionStrings,
      thinReport.swiftTypes,
      thinReport.swiftProtocols,
      thinReport.swiftProtocolConformances,
      thinReport.swiftFields,
      thinReport.dynamicSymbolTables,
      thinReport.dyldInfos,
      thinReport.chainedFixups,
      thinReport.dyldExportsTries,
      thinReport.dyldBindSymbols,
      thinReport.dyldExportSymbols,
      thinReport.objcSelectors,
      thinReport.objcClasses,
      thinReport.objcProtocols,
      thinReport.objcMethods,
      thinReport.objcIvars,
      thinReport.objcProperties,
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
    final encryptionInfos = <MachOEncryptionInfo>[];
    final segments = <MachOSegment>[];
    final symbolTables = <MachOSymbolTable>[];
    final symbols = <MachOSymbol>[];
    final sectionStrings = <MachOSectionString>[];
    final swiftTypes = <MachOSwiftType>[];
    final swiftProtocols = <MachOSwiftProtocol>[];
    final swiftProtocolConformances = <MachOSwiftProtocolConformance>[];
    final swiftFields = <MachOSwiftField>[];
    final dynamicSymbolTables = <MachODynamicSymbolTable>[];
    final dyldInfos = <MachODyldInfo>[];
    final chainedFixups = <MachOChainedFixups>[];
    final dyldExportsTries = <MachODyldExportsTrie>[];
    final dyldBindSymbols = <MachODyldBindSymbol>[];
    final dyldExportSymbols = <MachODyldExportSymbol>[];
    final objcSelectors = <MachOObjCSelector>[];
    final objcClasses = <MachOObjCClass>[];
    final objcProtocols = <MachOObjCProtocol>[];
    final objcMethods = <MachOObjCMethod>[];
    final objcIvars = <MachOObjCIvar>[];
    final objcProperties = <MachOObjCProperty>[];

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
      encryptionInfos.addAll(sliceReport.encryptionInfos);
      segments.addAll(sliceReport.segments);
      symbolTables.addAll(sliceReport.symbolTables);
      symbols.addAll(sliceReport.symbols);
      sectionStrings.addAll(sliceReport.sectionStrings);
      swiftTypes.addAll(sliceReport.swiftTypes);
      swiftProtocols.addAll(sliceReport.swiftProtocols);
      swiftProtocolConformances.addAll(sliceReport.swiftProtocolConformances);
      swiftFields.addAll(sliceReport.swiftFields);
      dynamicSymbolTables.addAll(sliceReport.dynamicSymbolTables);
      dyldInfos.addAll(sliceReport.dyldInfos);
      chainedFixups.addAll(sliceReport.chainedFixups);
      dyldExportsTries.addAll(sliceReport.dyldExportsTries);
      dyldBindSymbols.addAll(sliceReport.dyldBindSymbols);
      dyldExportSymbols.addAll(sliceReport.dyldExportSymbols);
      objcSelectors.addAll(sliceReport.objcSelectors);
      objcClasses.addAll(sliceReport.objcClasses);
      objcProtocols.addAll(sliceReport.objcProtocols);
      objcMethods.addAll(sliceReport.objcMethods);
      objcIvars.addAll(sliceReport.objcIvars);
      objcProperties.addAll(sliceReport.objcProperties);
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
      encryptionInfos,
      segments,
      symbolTables,
      symbols,
      sectionStrings,
      swiftTypes,
      swiftProtocols,
      swiftProtocolConformances,
      swiftFields,
      dynamicSymbolTables,
      dyldInfos,
      chainedFixups,
      dyldExportsTries,
      dyldBindSymbols,
      dyldExportSymbols,
      objcSelectors,
      objcClasses,
      objcProtocols,
      objcMethods,
      objcIvars,
      objcProperties,
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
    final dyldBindSymbols = _readDyldBindSymbolsFromFile(
      raf,
      fileOffset,
      availableLength,
      dyldInfos: report.dyldInfos,
    );
    final chainedFixupBindSymbols = _readChainedFixupBindSymbolsFromFile(
      raf,
      fileOffset,
      availableLength,
      chainedFixups: report.chainedFixups,
    );
    final dyldExportSymbols = _readDyldExportSymbolsFromFile(
      raf,
      fileOffset,
      availableLength,
      dyldInfos: report.dyldInfos,
      exportsTries: report.dyldExportsTries,
    );
    final sectionStrings = _readSectionStringsFromFile(
      raf,
      fileOffset,
      availableLength,
      segments: report.segments,
    );
    final swiftTypes = _readSwiftTypesFromFile(
      raf,
      fileOffset,
      availableLength,
      segments: report.segments,
    );
    final swiftProtocols = _readSwiftProtocolsFromFile(
      raf,
      fileOffset,
      availableLength,
      segments: report.segments,
    );
    final swiftProtocolConformances = _readSwiftProtocolConformancesFromFile(
      raf,
      fileOffset,
      availableLength,
      segments: report.segments,
    );
    final swiftFields = _readSwiftFieldsFromFile(
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
    final objcProtocols = _readObjCProtocolsFromFile(
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
    final objcIvars = _readObjCIvarsFromFile(
      raf,
      fileOffset,
      availableLength,
      is64Bit: thinIs64Bit,
      segments: report.segments,
    );
    final objcProperties = _readObjCPropertiesFromFile(
      raf,
      fileOffset,
      availableLength,
      is64Bit: thinIs64Bit,
      segments: report.segments,
    );
    if (symbols.isEmpty &&
        dyldBindSymbols.isEmpty &&
        chainedFixupBindSymbols.isEmpty &&
        dyldExportSymbols.isEmpty &&
        sectionStrings.isEmpty &&
        swiftTypes.isEmpty &&
        swiftProtocols.isEmpty &&
        swiftProtocolConformances.isEmpty &&
        swiftFields.isEmpty &&
        objcSelectors.isEmpty &&
        objcClasses.isEmpty &&
        objcProtocols.isEmpty &&
        objcMethods.isEmpty &&
        objcIvars.isEmpty &&
        objcProperties.isEmpty) {
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
      report.encryptionInfos,
      report.segments,
      report.symbolTables,
      [...report.symbols, ...symbols],
      [...report.sectionStrings, ...sectionStrings],
      [...report.swiftTypes, ...swiftTypes],
      [...report.swiftProtocols, ...swiftProtocols],
      [...report.swiftProtocolConformances, ...swiftProtocolConformances],
      [...report.swiftFields, ...swiftFields],
      report.dynamicSymbolTables,
      report.dyldInfos,
      report.chainedFixups,
      report.dyldExportsTries,
      [
        ...report.dyldBindSymbols,
        ...dyldBindSymbols,
        ...chainedFixupBindSymbols,
      ],
      [...report.dyldExportSymbols, ...dyldExportSymbols],
      [...report.objcSelectors, ...objcSelectors],
      [...report.objcClasses, ...objcClasses],
      [...report.objcProtocols, ...objcProtocols],
      [...report.objcMethods, ...objcMethods],
      [...report.objcIvars, ...objcIvars],
      [...report.objcProperties, ...objcProperties],
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
    final encryptionInfos = <MachOEncryptionInfo>[];
    final segments = <MachOSegment>[];
    final symbolTables = <MachOSymbolTable>[];
    final symbols = <MachOSymbol>[];
    final sectionStrings = <MachOSectionString>[];
    final swiftTypes = <MachOSwiftType>[];
    final swiftProtocols = <MachOSwiftProtocol>[];
    final swiftProtocolConformances = <MachOSwiftProtocolConformance>[];
    final swiftFields = <MachOSwiftField>[];
    final dynamicSymbolTables = <MachODynamicSymbolTable>[];
    final dyldInfos = <MachODyldInfo>[];
    final chainedFixups = <MachOChainedFixups>[];
    final dyldExportsTries = <MachODyldExportsTrie>[];
    final dyldBindSymbols = <MachODyldBindSymbol>[];
    final dyldExportSymbols = <MachODyldExportSymbol>[];
    final objcSelectors = <MachOObjCSelector>[];
    final objcClasses = <MachOObjCClass>[];
    final objcProtocols = <MachOObjCProtocol>[];
    final objcMethods = <MachOObjCMethod>[];
    final objcIvars = <MachOObjCIvar>[];
    final objcProperties = <MachOObjCProperty>[];

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
        encryptionInfos.addAll(sliceReport.encryptionInfos);
        segments.addAll(sliceReport.segments);
        symbolTables.addAll(sliceReport.symbolTables);
        symbols.addAll(sliceReport.symbols);
        sectionStrings.addAll(sliceReport.sectionStrings);
        swiftTypes.addAll(sliceReport.swiftTypes);
        swiftProtocols.addAll(sliceReport.swiftProtocols);
        swiftProtocolConformances.addAll(sliceReport.swiftProtocolConformances);
        swiftFields.addAll(sliceReport.swiftFields);
        dynamicSymbolTables.addAll(sliceReport.dynamicSymbolTables);
        dyldInfos.addAll(sliceReport.dyldInfos);
        chainedFixups.addAll(sliceReport.chainedFixups);
        dyldExportsTries.addAll(sliceReport.dyldExportsTries);
        dyldBindSymbols.addAll(sliceReport.dyldBindSymbols);
        dyldExportSymbols.addAll(sliceReport.dyldExportSymbols);
        objcSelectors.addAll(sliceReport.objcSelectors);
        objcClasses.addAll(sliceReport.objcClasses);
        objcProtocols.addAll(sliceReport.objcProtocols);
        objcMethods.addAll(sliceReport.objcMethods);
        objcIvars.addAll(sliceReport.objcIvars);
        objcProperties.addAll(sliceReport.objcProperties);
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
      encryptionInfos,
      segments,
      symbolTables,
      symbols,
      sectionStrings,
      swiftTypes,
      swiftProtocols,
      swiftProtocolConformances,
      swiftFields,
      dynamicSymbolTables,
      dyldInfos,
      chainedFixups,
      dyldExportsTries,
      dyldBindSymbols,
      dyldExportSymbols,
      objcSelectors,
      objcClasses,
      objcProtocols,
      objcMethods,
      objcIvars,
      objcProperties,
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
    final encryptionInfos = <MachOEncryptionInfo>[];
    final segments = <MachOSegment>[];
    final symbolTables = <MachOSymbolTable>[];
    final dynamicSymbolTables = <MachODynamicSymbolTable>[];
    final dyldInfos = <MachODyldInfo>[];
    final chainedFixups = <MachOChainedFixups>[];
    final dyldExportsTries = <MachODyldExportsTrie>[];
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

      if (_isDyldInfoCommand(command) && commandSize >= 48) {
        dyldInfos.add(
          MachODyldInfo(
            bindOffset: _readU32(bytes, offset + 16),
            bindSize: _readU32(bytes, offset + 20),
            weakBindOffset: _readU32(bytes, offset + 24),
            weakBindSize: _readU32(bytes, offset + 28),
            lazyBindOffset: _readU32(bytes, offset + 32),
            lazyBindSize: _readU32(bytes, offset + 36),
            exportOffset: _readU32(bytes, offset + 40),
            exportSize: _readU32(bytes, offset + 44),
          ),
        );
      }

      if (command == _lcDyldChainedFixups && commandSize >= 16) {
        chainedFixups.add(
          MachOChainedFixups(
            dataOffset: _readU32(bytes, offset + 8),
            dataSize: _readU32(bytes, offset + 12),
          ),
        );
      }

      if (command == _lcDyldExportsTrie && commandSize >= 16) {
        dyldExportsTries.add(
          MachODyldExportsTrie(
            dataOffset: _readU32(bytes, offset + 8),
            dataSize: _readU32(bytes, offset + 12),
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

      if (_isEncryptionInfoCommand(command, commandSize)) {
        encryptionInfos.add(
          MachOEncryptionInfo(
            cryptOffset: _readU32(bytes, offset + 8),
            cryptSize: _readU32(bytes, offset + 12),
            cryptId: _readU32(bytes, offset + 16),
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
    final dyldBindSymbols = _readDyldBindSymbolsFromBytes(
      bytes,
      dyldInfos: dyldInfos,
    );
    final chainedFixupBindSymbols = _readChainedFixupBindSymbolsFromBytes(
      bytes,
      chainedFixups: chainedFixups,
    );
    final dyldExportSymbols = _readDyldExportSymbolsFromBytes(
      bytes,
      dyldInfos: dyldInfos,
      exportsTries: dyldExportsTries,
    );
    final sectionStrings = _readSectionStringsFromBytes(
      bytes,
      segments: segments,
    );
    final swiftTypes = _readSwiftTypesFromBytes(bytes, segments: segments);
    final swiftProtocols = _readSwiftProtocolsFromBytes(
      bytes,
      segments: segments,
    );
    final swiftProtocolConformances = _readSwiftProtocolConformancesFromBytes(
      bytes,
      segments: segments,
    );
    final swiftFields = _readSwiftFieldsFromBytes(bytes, segments: segments);
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
    final objcProtocols = _readObjCProtocolsFromBytes(
      bytes,
      is64Bit: header.is64Bit,
      segments: segments,
    );
    final objcMethods = _readObjCMethodsFromBytes(
      bytes,
      is64Bit: header.is64Bit,
      segments: segments,
    );
    final objcIvars = _readObjCIvarsFromBytes(
      bytes,
      is64Bit: header.is64Bit,
      segments: segments,
    );
    final objcProperties = _readObjCPropertiesFromBytes(
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
      encryptionInfos: encryptionInfos,
      segments: segments,
      symbolTables: symbolTables,
      symbols: symbols,
      sectionStrings: sectionStrings,
      swiftTypes: swiftTypes,
      swiftProtocols: swiftProtocols,
      swiftProtocolConformances: swiftProtocolConformances,
      swiftFields: swiftFields,
      dynamicSymbolTables: dynamicSymbolTables,
      dyldInfos: dyldInfos,
      chainedFixups: chainedFixups,
      dyldExportsTries: dyldExportsTries,
      dyldBindSymbols: [...dyldBindSymbols, ...chainedFixupBindSymbols],
      dyldExportSymbols: dyldExportSymbols,
      objcSelectors: objcSelectors,
      objcClasses: objcClasses,
      objcProtocols: objcProtocols,
      objcMethods: objcMethods,
      objcIvars: objcIvars,
      objcProperties: objcProperties,
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
  List<MachOEncryptionInfo> encryptionInfos = const [],
  List<MachOSegment> segments = const [],
  List<MachOSymbolTable> symbolTables = const [],
  List<MachOSymbol> symbols = const [],
  List<MachOSectionString> sectionStrings = const [],
  List<MachOSwiftType> swiftTypes = const [],
  List<MachOSwiftProtocol> swiftProtocols = const [],
  List<MachOSwiftProtocolConformance> swiftProtocolConformances = const [],
  List<MachOSwiftField> swiftFields = const [],
  List<MachODynamicSymbolTable> dynamicSymbolTables = const [],
  List<MachODyldInfo> dyldInfos = const [],
  List<MachOChainedFixups> chainedFixups = const [],
  List<MachODyldExportsTrie> dyldExportsTries = const [],
  List<MachODyldBindSymbol> dyldBindSymbols = const [],
  List<MachODyldExportSymbol> dyldExportSymbols = const [],
  List<MachOObjCSelector> objcSelectors = const [],
  List<MachOObjCClass> objcClasses = const [],
  List<MachOObjCProtocol> objcProtocols = const [],
  List<MachOObjCMethod> objcMethods = const [],
  List<MachOObjCIvar> objcIvars = const [],
  List<MachOObjCProperty> objcProperties = const [],
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

  final byEncryptionInfo = <String, MachOEncryptionInfo>{};
  for (final encryptionInfo in encryptionInfos) {
    byEncryptionInfo['${encryptionInfo.cryptOffset}|${encryptionInfo.cryptSize}|${encryptionInfo.cryptId}'] =
        encryptionInfo;
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

  final bySwiftType = <String, MachOSwiftType>{};
  for (final swiftType in swiftTypes) {
    bySwiftType['${swiftType.sourceSection}|${swiftType.name}|${swiftType.descriptorAddress}'] =
        swiftType;
  }

  final bySwiftProtocol = <String, MachOSwiftProtocol>{};
  for (final protocol in swiftProtocols) {
    bySwiftProtocol['${protocol.sourceSection}|${protocol.name}|${protocol.descriptorAddress}'] =
        protocol;
  }

  final bySwiftProtocolConformance = <String, MachOSwiftProtocolConformance>{};
  for (final conformance in swiftProtocolConformances) {
    bySwiftProtocolConformance['${conformance.sourceSection}|${conformance.typeName}|${conformance.protocolName}|${conformance.descriptorAddress}'] =
        conformance;
  }

  final bySwiftField = <String, MachOSwiftField>{};
  for (final field in swiftFields) {
    bySwiftField['${field.sourceSection}|${field.ownerTypeName}|${field.name}|${field.fieldTypeName}|${field.descriptorAddress}'] =
        field;
  }

  final byDynamicSymbolTable = <String, MachODynamicSymbolTable>{};
  for (final dynamicSymbolTable in dynamicSymbolTables) {
    byDynamicSymbolTable['${dynamicSymbolTable.localSymbolIndex}|${dynamicSymbolTable.localSymbolCount}|${dynamicSymbolTable.externalSymbolIndex}|${dynamicSymbolTable.externalSymbolCount}|${dynamicSymbolTable.undefinedSymbolIndex}|${dynamicSymbolTable.undefinedSymbolCount}|${dynamicSymbolTable.indirectSymbolOffset}|${dynamicSymbolTable.indirectSymbolCount}'] =
        dynamicSymbolTable;
  }

  final byDyldInfo = <String, MachODyldInfo>{};
  for (final dyldInfo in dyldInfos) {
    byDyldInfo['${dyldInfo.bindOffset}|${dyldInfo.bindSize}|${dyldInfo.weakBindOffset}|${dyldInfo.weakBindSize}|${dyldInfo.lazyBindOffset}|${dyldInfo.lazyBindSize}|${dyldInfo.exportOffset}|${dyldInfo.exportSize}'] =
        dyldInfo;
  }

  final byChainedFixups = <String, MachOChainedFixups>{};
  for (final chainedFixup in chainedFixups) {
    byChainedFixups['${chainedFixup.dataOffset}|${chainedFixup.dataSize}'] =
        chainedFixup;
  }

  final byDyldExportsTrie = <String, MachODyldExportsTrie>{};
  for (final exportsTrie in dyldExportsTries) {
    byDyldExportsTrie['${exportsTrie.dataOffset}|${exportsTrie.dataSize}'] =
        exportsTrie;
  }

  final byDyldBindSymbol = <String, MachODyldBindSymbol>{};
  for (final dyldBindSymbol in dyldBindSymbols) {
    byDyldBindSymbol['${dyldBindSymbol.source}|${dyldBindSymbol.name}'] =
        dyldBindSymbol;
  }

  final byDyldExportSymbol = <String, MachODyldExportSymbol>{};
  for (final dyldExportSymbol in dyldExportSymbols) {
    byDyldExportSymbol['${dyldExportSymbol.source}|${dyldExportSymbol.name}'] =
        dyldExportSymbol;
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

  final byObjCProtocol = <String, MachOObjCProtocol>{};
  for (final objcProtocol in objcProtocols) {
    byObjCProtocol['${objcProtocol.sourceSection}|${objcProtocol.name}|${objcProtocol.protocolAddress}'] =
        objcProtocol;
  }

  final byObjCMethod = <String, MachOObjCMethod>{};
  for (final objcMethod in objcMethods) {
    byObjCMethod['${objcMethod.className}|${objcMethod.sourceSection}|${objcMethod.name}|${objcMethod.methodListAddress}'] =
        objcMethod;
  }

  final byObjCIvar = <String, MachOObjCIvar>{};
  for (final ivar in objcIvars) {
    byObjCIvar['${ivar.className}|${ivar.sourceSection}|${ivar.name}|${ivar.typeEncoding}|${ivar.ivarListAddress}'] =
        ivar;
  }

  final byObjCProperty = <String, MachOObjCProperty>{};
  for (final property in objcProperties) {
    byObjCProperty['${property.className}|${property.sourceSection}|${property.name}|${property.attributes}|${property.propertyListAddress}'] =
        property;
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
    encryptionInfos: byEncryptionInfo.values.toList(),
    segments: [
      for (final entry in sectionsBySegment.entries)
        MachOSegment(name: entry.key, sections: entry.value.values.toList()),
    ],
    symbolTables: bySymbolTable.values.toList(),
    symbols: bySymbol.values.toList(),
    sectionStrings: bySectionString.values.toList(),
    swiftTypes: bySwiftType.values.toList(),
    swiftProtocols: bySwiftProtocol.values.toList(),
    swiftProtocolConformances: bySwiftProtocolConformance.values.toList(),
    swiftFields: bySwiftField.values.toList(),
    dynamicSymbolTables: byDynamicSymbolTable.values.toList(),
    dyldInfos: byDyldInfo.values.toList(),
    chainedFixups: byChainedFixups.values.toList(),
    dyldExportsTries: byDyldExportsTrie.values.toList(),
    dyldBindSymbols: byDyldBindSymbol.values.toList(),
    dyldExportSymbols: byDyldExportSymbol.values.toList(),
    objcSelectors: byObjCSelector.values.toList(),
    objcClasses: byObjCClass.values.toList(),
    objcProtocols: byObjCProtocol.values.toList(),
    objcMethods: byObjCMethod.values.toList(),
    objcIvars: byObjCIvar.values.toList(),
    objcProperties: byObjCProperty.values.toList(),
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

class _Uleb128Result {
  const _Uleb128Result({required this.value, required this.nextOffset});

  final int value;
  final int nextOffset;
}

class _ObjCClassMetadata {
  const _ObjCClassMetadata({
    required this.name,
    required this.classRoAddress,
    required this.baseMethodsAddress,
    required this.protocolsAddress,
    required this.ivarsAddress,
    required this.basePropertiesAddress,
  });

  final String name;
  final int classRoAddress;
  final int baseMethodsAddress;
  final int protocolsAddress;
  final int ivarsAddress;
  final int basePropertiesAddress;
}

class _ObjCCategoryMetadata {
  const _ObjCCategoryMetadata({
    required this.ownerName,
    required this.instanceMethodsAddress,
    required this.classMethodsAddress,
    required this.protocolsAddress,
    required this.instancePropertiesAddress,
    required this.classPropertiesAddress,
  });

  final String ownerName;
  final int instanceMethodsAddress;
  final int classMethodsAddress;
  final int protocolsAddress;
  final int instancePropertiesAddress;
  final int classPropertiesAddress;
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

bool _isDyldInfoCommand(int command) {
  return command == _lcDyldInfo || command == _lcDyldInfoOnly;
}

bool _isEncryptionInfoCommand(int command, int commandSize) {
  return (command == _lcEncryptionInfo && commandSize >= 20) ||
      (command == _lcEncryptionInfo64 && commandSize >= 24);
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

List<MachOSwiftType> _readSwiftTypesFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required List<MachOSegment> segments,
}) {
  final swiftTypes = <MachOSwiftType>[];
  final allSections = _allSections(segments).toList();

  for (final section in _sectionsNamed(segments, '__swift5_types')) {
    if (!_canReadSection(section, availableLength)) continue;

    final sectionBytes = _readRange(
      raf,
      fileOffset + section.fileOffset,
      section.size,
    );
    for (var offset = 0; offset + 4 <= sectionBytes.length; offset += 4) {
      final entryAddress = section.address + offset;
      final descriptorAddress = entryAddress + _readI32(sectionBytes, offset);
      if (descriptorAddress <= 0) continue;

      final name = _readSwiftTypeNameFromFile(
        raf,
        fileOffset,
        availableLength,
        allSections,
        descriptorAddress,
      );
      if (name == null) continue;

      swiftTypes.add(
        MachOSwiftType(
          name: name,
          sourceSection: section.displayName,
          descriptorAddress: descriptorAddress,
        ),
      );
    }
  }

  return swiftTypes;
}

List<MachOSwiftProtocol> _readSwiftProtocolsFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required List<MachOSegment> segments,
}) {
  final protocols = <MachOSwiftProtocol>[];
  final allSections = _allSections(segments).toList();

  for (final section in _sectionsNamed(segments, '__swift5_protos')) {
    if (!_canReadSection(section, availableLength)) continue;

    final sectionBytes = _readRange(
      raf,
      fileOffset + section.fileOffset,
      section.size,
    );
    for (var offset = 0; offset + 4 <= sectionBytes.length; offset += 4) {
      final entryAddress = section.address + offset;
      final descriptorAddress = entryAddress + _readI32(sectionBytes, offset);
      if (descriptorAddress <= 0) continue;

      final name = _readSwiftProtocolNameFromFile(
        raf,
        fileOffset,
        availableLength,
        allSections,
        descriptorAddress,
      );
      if (name == null) continue;

      protocols.add(
        MachOSwiftProtocol(
          name: name,
          sourceSection: section.displayName,
          descriptorAddress: descriptorAddress,
        ),
      );
    }
  }

  return protocols;
}

List<MachOSwiftProtocolConformance> _readSwiftProtocolConformancesFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required List<MachOSegment> segments,
}) {
  final conformances = <MachOSwiftProtocolConformance>[];
  final allSections = _allSections(segments).toList();

  for (final section in _sectionsNamed(segments, '__swift5_proto')) {
    if (!_canReadSection(section, availableLength)) continue;

    final sectionBytes = _readRange(
      raf,
      fileOffset + section.fileOffset,
      section.size,
    );
    for (var offset = 0; offset + 4 <= sectionBytes.length; offset += 4) {
      final entryAddress = section.address + offset;
      final descriptorAddress = entryAddress + _readI32(sectionBytes, offset);
      if (descriptorAddress <= 0) continue;

      final conformance = _readSwiftProtocolConformanceFromFile(
        raf,
        fileOffset,
        availableLength,
        allSections,
        section.displayName,
        descriptorAddress,
      );
      if (conformance == null) continue;

      conformances.add(conformance);
    }
  }

  return conformances;
}

List<MachOSwiftField> _readSwiftFieldsFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required List<MachOSegment> segments,
}) {
  final fields = <MachOSwiftField>[];
  final allSections = _allSections(segments).toList();

  for (final section in _sectionsNamed(segments, '__swift5_fieldmd')) {
    if (!_canReadSection(section, availableLength)) continue;

    final sectionBytes = _readRange(
      raf,
      fileOffset + section.fileOffset,
      section.size,
    );
    var offset = 0;
    while (offset + _swiftFieldDescriptorHeaderBytes <= sectionBytes.length) {
      final descriptorAddress = section.address + offset;
      final fieldRecordSize = _readU16(sectionBytes, offset + 10);
      final fieldCount = _readU32(sectionBytes, offset + 12);
      final descriptorByteLength = _swiftFieldDescriptorByteLength(
        fieldRecordSize,
        fieldCount,
      );
      if (descriptorByteLength == null ||
          offset + descriptorByteLength > sectionBytes.length) {
        break;
      }

      final ownerTypeName = _readRelativeSwiftStringFromFile(
        raf,
        fileOffset,
        availableLength,
        allSections,
        pointerAddress: descriptorAddress,
        relativeOffset: _readI32(sectionBytes, offset),
      );
      for (var i = 0; i < fieldCount; i += 1) {
        final recordOffset =
            offset + _swiftFieldDescriptorHeaderBytes + i * fieldRecordSize;
        final recordAddress = section.address + recordOffset;
        final fieldTypeName = _readRelativeSwiftStringFromFile(
          raf,
          fileOffset,
          availableLength,
          allSections,
          pointerAddress: recordAddress + 4,
          relativeOffset: _readI32(sectionBytes, recordOffset + 4),
        );
        final fieldName = _readRelativeSwiftStringFromFile(
          raf,
          fileOffset,
          availableLength,
          allSections,
          pointerAddress: recordAddress + 8,
          relativeOffset: _readI32(sectionBytes, recordOffset + 8),
        );
        if (fieldName == null) continue;

        fields.add(
          MachOSwiftField(
            name: fieldName,
            ownerTypeName: ownerTypeName,
            fieldTypeName: fieldTypeName,
            sourceSection: section.displayName,
            descriptorAddress: descriptorAddress,
          ),
        );
      }

      offset += descriptorByteLength;
    }
  }

  return fields;
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
  final allSections = _allSections(segments).toList();
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
      final targetAddress = _readPointerValue(
        sectionBytes,
        offset,
        allSections,
        is64Bit: is64Bit,
      );
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
      final classAddress = _readPointerValue(
        sectionBytes,
        offset,
        allSections,
        is64Bit: is64Bit,
      );
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

List<MachOObjCProtocol> _readObjCProtocolsFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required bool is64Bit,
  required List<MachOSegment> segments,
}) {
  final protocols = <MachOObjCProtocol>[];
  final pointerSize = is64Bit ? 8 : 4;
  final allSections = _allSections(segments).toList();
  final stringSections = _stringSections(segments).toList();

  for (final section in _objcProtocolReferenceSections(segments)) {
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
      final protocolAddress = _readPointerValue(
        sectionBytes,
        offset,
        allSections,
        is64Bit: is64Bit,
      );
      final name = _readObjCProtocolNameFromFile(
        raf,
        fileOffset,
        availableLength,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        protocolAddress: protocolAddress,
      );
      if (name == null) continue;

      protocols.add(
        MachOObjCProtocol(
          name: name,
          sourceSection: section.displayName,
          protocolAddress: protocolAddress,
        ),
      );
      protocols.addAll(
        _readObjCInheritedProtocolsFromFile(
          raf,
          fileOffset,
          availableLength,
          is64Bit: is64Bit,
          allSections: allSections,
          stringSections: stringSections,
          protocolAddress: protocolAddress,
          visitedProtocolAddresses: {protocolAddress},
        ),
      );
    }
  }

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
      final classAddress = _readPointerValue(
        sectionBytes,
        offset,
        allSections,
        is64Bit: is64Bit,
      );
      final metadata = _readObjCClassMetadataFromFile(
        raf,
        fileOffset,
        availableLength,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        classAddress: classAddress,
      );
      if (metadata == null || metadata.protocolsAddress == 0) continue;

      protocols.addAll(
        _readObjCProtocolListFromFile(
          raf,
          fileOffset,
          availableLength,
          is64Bit: is64Bit,
          allSections: allSections,
          stringSections: stringSections,
          protocolListAddress: metadata.protocolsAddress,
        ),
      );
    }
  }

  for (final section in _objcCategoryListSections(segments)) {
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
      final categoryAddress = _readPointerValue(
        sectionBytes,
        offset,
        allSections,
        is64Bit: is64Bit,
      );
      final metadata = _readObjCCategoryMetadataFromFile(
        raf,
        fileOffset,
        availableLength,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        categoryAddress: categoryAddress,
      );
      if (metadata == null || metadata.protocolsAddress == 0) continue;

      protocols.addAll(
        _readObjCProtocolListFromFile(
          raf,
          fileOffset,
          availableLength,
          is64Bit: is64Bit,
          allSections: allSections,
          stringSections: stringSections,
          protocolListAddress: metadata.protocolsAddress,
        ),
      );
    }
  }

  return protocols;
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
      final classAddress = _readPointerValue(
        sectionBytes,
        offset,
        allSections,
        is64Bit: is64Bit,
      );
      final metadata = _readObjCClassMetadataFromFile(
        raf,
        fileOffset,
        availableLength,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        classAddress: classAddress,
      );
      if (metadata == null) continue;

      if (metadata.baseMethodsAddress != 0) {
        methods.addAll(
          _readObjCMethodListsFromFile(
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
      final metaclassAddress = _readPointerAtAddressFromFile(
        raf,
        fileOffset,
        availableLength,
        allSections,
        classAddress,
        is64Bit: is64Bit,
      );
      if (metaclassAddress != null &&
          metaclassAddress != 0 &&
          metaclassAddress != classAddress) {
        final metaclassMetadata = _readObjCClassMetadataFromFile(
          raf,
          fileOffset,
          availableLength,
          is64Bit: is64Bit,
          allSections: allSections,
          stringSections: stringSections,
          classAddress: metaclassAddress,
        );
        if (metaclassMetadata != null &&
            metaclassMetadata.baseMethodsAddress != 0) {
          methods.addAll(
            _readObjCMethodListsFromFile(
              raf,
              fileOffset,
              availableLength,
              is64Bit: is64Bit,
              allSections: allSections,
              stringSections: stringSections,
              className: metadata.name,
              methodListAddress: metaclassMetadata.baseMethodsAddress,
            ),
          );
        }
      }
      if (metadata.protocolsAddress != 0) {
        methods.addAll(
          _readObjCProtocolListMethodsFromFile(
            raf,
            fileOffset,
            availableLength,
            is64Bit: is64Bit,
            allSections: allSections,
            stringSections: stringSections,
            protocolListAddress: metadata.protocolsAddress,
          ),
        );
      }
    }
  }

  for (final section in _objcProtocolReferenceSections(segments)) {
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
      final protocolAddress = _readPointerValue(
        sectionBytes,
        offset,
        allSections,
        is64Bit: is64Bit,
      );
      methods.addAll(
        _readObjCProtocolMethodsFromFile(
          raf,
          fileOffset,
          availableLength,
          is64Bit: is64Bit,
          allSections: allSections,
          stringSections: stringSections,
          protocolAddress: protocolAddress,
        ),
      );
    }
  }

  for (final section in _objcCategoryListSections(segments)) {
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
      final categoryAddress = _readPointerValue(
        sectionBytes,
        offset,
        allSections,
        is64Bit: is64Bit,
      );
      final metadata = _readObjCCategoryMetadataFromFile(
        raf,
        fileOffset,
        availableLength,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        categoryAddress: categoryAddress,
      );
      if (metadata == null) continue;

      methods.addAll(
        _readObjCCategoryMethodListsFromFile(
          raf,
          fileOffset,
          availableLength,
          is64Bit: is64Bit,
          allSections: allSections,
          stringSections: stringSections,
          metadata: metadata,
        ),
      );
      if (metadata.protocolsAddress != 0) {
        methods.addAll(
          _readObjCProtocolListMethodsFromFile(
            raf,
            fileOffset,
            availableLength,
            is64Bit: is64Bit,
            allSections: allSections,
            stringSections: stringSections,
            protocolListAddress: metadata.protocolsAddress,
          ),
        );
      }
    }
  }

  return methods;
}

List<MachOObjCIvar> _readObjCIvarsFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required bool is64Bit,
  required List<MachOSegment> segments,
}) {
  final ivars = <MachOObjCIvar>[];
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
      final classAddress = _readPointerValue(
        sectionBytes,
        offset,
        allSections,
        is64Bit: is64Bit,
      );
      final metadata = _readObjCClassMetadataFromFile(
        raf,
        fileOffset,
        availableLength,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        classAddress: classAddress,
      );
      if (metadata == null || metadata.ivarsAddress == 0) continue;

      ivars.addAll(
        _readObjCIvarListFromFile(
          raf,
          fileOffset,
          availableLength,
          is64Bit: is64Bit,
          allSections: allSections,
          stringSections: stringSections,
          className: metadata.name,
          ivarListAddress: metadata.ivarsAddress,
        ),
      );
    }
  }

  return ivars;
}

List<MachOObjCProperty> _readObjCPropertiesFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required bool is64Bit,
  required List<MachOSegment> segments,
}) {
  final properties = <MachOObjCProperty>[];
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
      final classAddress = _readPointerValue(
        sectionBytes,
        offset,
        allSections,
        is64Bit: is64Bit,
      );
      final metadata = _readObjCClassMetadataFromFile(
        raf,
        fileOffset,
        availableLength,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        classAddress: classAddress,
      );
      if (metadata == null) continue;

      if (metadata.basePropertiesAddress != 0) {
        properties.addAll(
          _readObjCPropertyListFromFile(
            raf,
            fileOffset,
            availableLength,
            is64Bit: is64Bit,
            allSections: allSections,
            stringSections: stringSections,
            className: metadata.name,
            propertyListAddress: metadata.basePropertiesAddress,
          ),
        );
      }
      final metaclassAddress = _readPointerAtAddressFromFile(
        raf,
        fileOffset,
        availableLength,
        allSections,
        classAddress,
        is64Bit: is64Bit,
      );
      if (metaclassAddress != null &&
          metaclassAddress != 0 &&
          metaclassAddress != classAddress) {
        final metaclassMetadata = _readObjCClassMetadataFromFile(
          raf,
          fileOffset,
          availableLength,
          is64Bit: is64Bit,
          allSections: allSections,
          stringSections: stringSections,
          classAddress: metaclassAddress,
        );
        if (metaclassMetadata != null &&
            metaclassMetadata.basePropertiesAddress != 0) {
          properties.addAll(
            _readObjCPropertyListFromFile(
              raf,
              fileOffset,
              availableLength,
              is64Bit: is64Bit,
              allSections: allSections,
              stringSections: stringSections,
              className: metadata.name,
              propertyListAddress: metaclassMetadata.basePropertiesAddress,
            ),
          );
        }
      }
      if (metadata.protocolsAddress != 0) {
        properties.addAll(
          _readObjCProtocolListPropertiesFromFile(
            raf,
            fileOffset,
            availableLength,
            is64Bit: is64Bit,
            allSections: allSections,
            stringSections: stringSections,
            protocolListAddress: metadata.protocolsAddress,
          ),
        );
      }
    }
  }

  for (final section in _objcProtocolReferenceSections(segments)) {
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
      final protocolAddress = _readPointerValue(
        sectionBytes,
        offset,
        allSections,
        is64Bit: is64Bit,
      );
      properties.addAll(
        _readObjCProtocolPropertiesFromFile(
          raf,
          fileOffset,
          availableLength,
          is64Bit: is64Bit,
          allSections: allSections,
          stringSections: stringSections,
          protocolAddress: protocolAddress,
        ),
      );
    }
  }

  for (final section in _objcCategoryListSections(segments)) {
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
      final categoryAddress = _readPointerValue(
        sectionBytes,
        offset,
        allSections,
        is64Bit: is64Bit,
      );
      final metadata = _readObjCCategoryMetadataFromFile(
        raf,
        fileOffset,
        availableLength,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        categoryAddress: categoryAddress,
      );
      if (metadata == null) continue;

      if (metadata.instancePropertiesAddress != 0) {
        properties.addAll(
          _readObjCPropertyListFromFile(
            raf,
            fileOffset,
            availableLength,
            is64Bit: is64Bit,
            allSections: allSections,
            stringSections: stringSections,
            className: metadata.ownerName,
            propertyListAddress: metadata.instancePropertiesAddress,
          ),
        );
      }
      if (metadata.classPropertiesAddress != 0) {
        properties.addAll(
          _readObjCPropertyListFromFile(
            raf,
            fileOffset,
            availableLength,
            is64Bit: is64Bit,
            allSections: allSections,
            stringSections: stringSections,
            className: metadata.ownerName,
            propertyListAddress: metadata.classPropertiesAddress,
          ),
        );
      }
      if (metadata.protocolsAddress != 0) {
        properties.addAll(
          _readObjCProtocolListPropertiesFromFile(
            raf,
            fileOffset,
            availableLength,
            is64Bit: is64Bit,
            allSections: allSections,
            stringSections: stringSections,
            protocolListAddress: metadata.protocolsAddress,
          ),
        );
      }
    }
  }

  return properties;
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

List<MachOSwiftType> _readSwiftTypesFromBytes(
  List<int> bytes, {
  required List<MachOSegment> segments,
}) {
  final swiftTypes = <MachOSwiftType>[];
  final allSections = _allSections(segments).toList();

  for (final section in _sectionsNamed(segments, '__swift5_types')) {
    if (!_canReadSection(section, bytes.length)) continue;

    final sectionBytes = bytes.sublist(
      section.fileOffset,
      section.fileOffset + section.size,
    );
    for (var offset = 0; offset + 4 <= sectionBytes.length; offset += 4) {
      final entryAddress = section.address + offset;
      final descriptorAddress = entryAddress + _readI32(sectionBytes, offset);
      if (descriptorAddress <= 0) continue;

      final name = _readSwiftTypeNameFromBytes(
        bytes,
        allSections,
        descriptorAddress,
      );
      if (name == null) continue;

      swiftTypes.add(
        MachOSwiftType(
          name: name,
          sourceSection: section.displayName,
          descriptorAddress: descriptorAddress,
        ),
      );
    }
  }

  return swiftTypes;
}

List<MachOSwiftProtocol> _readSwiftProtocolsFromBytes(
  List<int> bytes, {
  required List<MachOSegment> segments,
}) {
  final protocols = <MachOSwiftProtocol>[];
  final allSections = _allSections(segments).toList();

  for (final section in _sectionsNamed(segments, '__swift5_protos')) {
    if (!_canReadSection(section, bytes.length)) continue;

    final sectionBytes = bytes.sublist(
      section.fileOffset,
      section.fileOffset + section.size,
    );
    for (var offset = 0; offset + 4 <= sectionBytes.length; offset += 4) {
      final entryAddress = section.address + offset;
      final descriptorAddress = entryAddress + _readI32(sectionBytes, offset);
      if (descriptorAddress <= 0) continue;

      final name = _readSwiftProtocolNameFromBytes(
        bytes,
        allSections,
        descriptorAddress,
      );
      if (name == null) continue;

      protocols.add(
        MachOSwiftProtocol(
          name: name,
          sourceSection: section.displayName,
          descriptorAddress: descriptorAddress,
        ),
      );
    }
  }

  return protocols;
}

List<MachOSwiftProtocolConformance> _readSwiftProtocolConformancesFromBytes(
  List<int> bytes, {
  required List<MachOSegment> segments,
}) {
  final conformances = <MachOSwiftProtocolConformance>[];
  final allSections = _allSections(segments).toList();

  for (final section in _sectionsNamed(segments, '__swift5_proto')) {
    if (!_canReadSection(section, bytes.length)) continue;

    final sectionBytes = bytes.sublist(
      section.fileOffset,
      section.fileOffset + section.size,
    );
    for (var offset = 0; offset + 4 <= sectionBytes.length; offset += 4) {
      final entryAddress = section.address + offset;
      final descriptorAddress = entryAddress + _readI32(sectionBytes, offset);
      if (descriptorAddress <= 0) continue;

      final conformance = _readSwiftProtocolConformanceFromBytes(
        bytes,
        allSections,
        section.displayName,
        descriptorAddress,
      );
      if (conformance == null) continue;

      conformances.add(conformance);
    }
  }

  return conformances;
}

List<MachOSwiftField> _readSwiftFieldsFromBytes(
  List<int> bytes, {
  required List<MachOSegment> segments,
}) {
  final fields = <MachOSwiftField>[];
  final allSections = _allSections(segments).toList();

  for (final section in _sectionsNamed(segments, '__swift5_fieldmd')) {
    if (!_canReadSection(section, bytes.length)) continue;

    final sectionBytes = bytes.sublist(
      section.fileOffset,
      section.fileOffset + section.size,
    );
    var offset = 0;
    while (offset + _swiftFieldDescriptorHeaderBytes <= sectionBytes.length) {
      final descriptorAddress = section.address + offset;
      final fieldRecordSize = _readU16(sectionBytes, offset + 10);
      final fieldCount = _readU32(sectionBytes, offset + 12);
      final descriptorByteLength = _swiftFieldDescriptorByteLength(
        fieldRecordSize,
        fieldCount,
      );
      if (descriptorByteLength == null ||
          offset + descriptorByteLength > sectionBytes.length) {
        break;
      }

      final ownerTypeName = _readRelativeSwiftStringFromBytes(
        bytes,
        allSections,
        pointerAddress: descriptorAddress,
        relativeOffset: _readI32(sectionBytes, offset),
      );
      for (var i = 0; i < fieldCount; i += 1) {
        final recordOffset =
            offset + _swiftFieldDescriptorHeaderBytes + i * fieldRecordSize;
        final recordAddress = section.address + recordOffset;
        final fieldTypeName = _readRelativeSwiftStringFromBytes(
          bytes,
          allSections,
          pointerAddress: recordAddress + 4,
          relativeOffset: _readI32(sectionBytes, recordOffset + 4),
        );
        final fieldName = _readRelativeSwiftStringFromBytes(
          bytes,
          allSections,
          pointerAddress: recordAddress + 8,
          relativeOffset: _readI32(sectionBytes, recordOffset + 8),
        );
        if (fieldName == null) continue;

        fields.add(
          MachOSwiftField(
            name: fieldName,
            ownerTypeName: ownerTypeName,
            fieldTypeName: fieldTypeName,
            sourceSection: section.displayName,
            descriptorAddress: descriptorAddress,
          ),
        );
      }

      offset += descriptorByteLength;
    }
  }

  return fields;
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
      final classAddress = _readPointerValue(
        sectionBytes,
        offset,
        allSections,
        is64Bit: is64Bit,
      );
      final metadata = _readObjCClassMetadataFromBytes(
        bytes,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        classAddress: classAddress,
      );
      if (metadata == null) continue;

      if (metadata.baseMethodsAddress != 0) {
        methods.addAll(
          _readObjCMethodListsFromBytes(
            bytes,
            is64Bit: is64Bit,
            allSections: allSections,
            stringSections: stringSections,
            className: metadata.name,
            methodListAddress: metadata.baseMethodsAddress,
          ),
        );
      }
      final metaclassAddress = _readPointerAtAddressFromBytes(
        bytes,
        allSections,
        classAddress,
        is64Bit: is64Bit,
      );
      if (metaclassAddress != null &&
          metaclassAddress != 0 &&
          metaclassAddress != classAddress) {
        final metaclassMetadata = _readObjCClassMetadataFromBytes(
          bytes,
          is64Bit: is64Bit,
          allSections: allSections,
          stringSections: stringSections,
          classAddress: metaclassAddress,
        );
        if (metaclassMetadata != null &&
            metaclassMetadata.baseMethodsAddress != 0) {
          methods.addAll(
            _readObjCMethodListsFromBytes(
              bytes,
              is64Bit: is64Bit,
              allSections: allSections,
              stringSections: stringSections,
              className: metadata.name,
              methodListAddress: metaclassMetadata.baseMethodsAddress,
            ),
          );
        }
      }
      if (metadata.protocolsAddress != 0) {
        methods.addAll(
          _readObjCProtocolListMethodsFromBytes(
            bytes,
            is64Bit: is64Bit,
            allSections: allSections,
            stringSections: stringSections,
            protocolListAddress: metadata.protocolsAddress,
          ),
        );
      }
    }
  }

  for (final section in _objcProtocolReferenceSections(segments)) {
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
      final protocolAddress = _readPointerValue(
        sectionBytes,
        offset,
        allSections,
        is64Bit: is64Bit,
      );
      methods.addAll(
        _readObjCProtocolMethodsFromBytes(
          bytes,
          is64Bit: is64Bit,
          allSections: allSections,
          stringSections: stringSections,
          protocolAddress: protocolAddress,
        ),
      );
    }
  }

  for (final section in _objcCategoryListSections(segments)) {
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
      final categoryAddress = _readPointerValue(
        sectionBytes,
        offset,
        allSections,
        is64Bit: is64Bit,
      );
      final metadata = _readObjCCategoryMetadataFromBytes(
        bytes,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        categoryAddress: categoryAddress,
      );
      if (metadata == null) continue;

      methods.addAll(
        _readObjCCategoryMethodListsFromBytes(
          bytes,
          is64Bit: is64Bit,
          allSections: allSections,
          stringSections: stringSections,
          metadata: metadata,
        ),
      );
      if (metadata.protocolsAddress != 0) {
        methods.addAll(
          _readObjCProtocolListMethodsFromBytes(
            bytes,
            is64Bit: is64Bit,
            allSections: allSections,
            stringSections: stringSections,
            protocolListAddress: metadata.protocolsAddress,
          ),
        );
      }
    }
  }

  return methods;
}

List<MachOObjCIvar> _readObjCIvarsFromBytes(
  List<int> bytes, {
  required bool is64Bit,
  required List<MachOSegment> segments,
}) {
  final ivars = <MachOObjCIvar>[];
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
      final classAddress = _readPointerValue(
        sectionBytes,
        offset,
        allSections,
        is64Bit: is64Bit,
      );
      final metadata = _readObjCClassMetadataFromBytes(
        bytes,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        classAddress: classAddress,
      );
      if (metadata == null || metadata.ivarsAddress == 0) continue;

      ivars.addAll(
        _readObjCIvarListFromBytes(
          bytes,
          is64Bit: is64Bit,
          allSections: allSections,
          stringSections: stringSections,
          className: metadata.name,
          ivarListAddress: metadata.ivarsAddress,
        ),
      );
    }
  }

  return ivars;
}

List<MachOObjCProperty> _readObjCPropertiesFromBytes(
  List<int> bytes, {
  required bool is64Bit,
  required List<MachOSegment> segments,
}) {
  final properties = <MachOObjCProperty>[];
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
      final classAddress = _readPointerValue(
        sectionBytes,
        offset,
        allSections,
        is64Bit: is64Bit,
      );
      final metadata = _readObjCClassMetadataFromBytes(
        bytes,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        classAddress: classAddress,
      );
      if (metadata == null) continue;

      if (metadata.basePropertiesAddress != 0) {
        properties.addAll(
          _readObjCPropertyListFromBytes(
            bytes,
            is64Bit: is64Bit,
            allSections: allSections,
            stringSections: stringSections,
            className: metadata.name,
            propertyListAddress: metadata.basePropertiesAddress,
          ),
        );
      }
      final metaclassAddress = _readPointerAtAddressFromBytes(
        bytes,
        allSections,
        classAddress,
        is64Bit: is64Bit,
      );
      if (metaclassAddress != null &&
          metaclassAddress != 0 &&
          metaclassAddress != classAddress) {
        final metaclassMetadata = _readObjCClassMetadataFromBytes(
          bytes,
          is64Bit: is64Bit,
          allSections: allSections,
          stringSections: stringSections,
          classAddress: metaclassAddress,
        );
        if (metaclassMetadata != null &&
            metaclassMetadata.basePropertiesAddress != 0) {
          properties.addAll(
            _readObjCPropertyListFromBytes(
              bytes,
              is64Bit: is64Bit,
              allSections: allSections,
              stringSections: stringSections,
              className: metadata.name,
              propertyListAddress: metaclassMetadata.basePropertiesAddress,
            ),
          );
        }
      }
      if (metadata.protocolsAddress != 0) {
        properties.addAll(
          _readObjCProtocolListPropertiesFromBytes(
            bytes,
            is64Bit: is64Bit,
            allSections: allSections,
            stringSections: stringSections,
            protocolListAddress: metadata.protocolsAddress,
          ),
        );
      }
    }
  }

  for (final section in _objcProtocolReferenceSections(segments)) {
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
      final protocolAddress = _readPointerValue(
        sectionBytes,
        offset,
        allSections,
        is64Bit: is64Bit,
      );
      properties.addAll(
        _readObjCProtocolPropertiesFromBytes(
          bytes,
          is64Bit: is64Bit,
          allSections: allSections,
          stringSections: stringSections,
          protocolAddress: protocolAddress,
        ),
      );
    }
  }

  for (final section in _objcCategoryListSections(segments)) {
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
      final categoryAddress = _readPointerValue(
        sectionBytes,
        offset,
        allSections,
        is64Bit: is64Bit,
      );
      final metadata = _readObjCCategoryMetadataFromBytes(
        bytes,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        categoryAddress: categoryAddress,
      );
      if (metadata == null) continue;

      if (metadata.instancePropertiesAddress != 0) {
        properties.addAll(
          _readObjCPropertyListFromBytes(
            bytes,
            is64Bit: is64Bit,
            allSections: allSections,
            stringSections: stringSections,
            className: metadata.ownerName,
            propertyListAddress: metadata.instancePropertiesAddress,
          ),
        );
      }
      if (metadata.classPropertiesAddress != 0) {
        properties.addAll(
          _readObjCPropertyListFromBytes(
            bytes,
            is64Bit: is64Bit,
            allSections: allSections,
            stringSections: stringSections,
            className: metadata.ownerName,
            propertyListAddress: metadata.classPropertiesAddress,
          ),
        );
      }
      if (metadata.protocolsAddress != 0) {
        properties.addAll(
          _readObjCProtocolListPropertiesFromBytes(
            bytes,
            is64Bit: is64Bit,
            allSections: allSections,
            stringSections: stringSections,
            protocolListAddress: metadata.protocolsAddress,
          ),
        );
      }
    }
  }

  return properties;
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
      final classAddress = _readPointerValue(
        sectionBytes,
        offset,
        allSections,
        is64Bit: is64Bit,
      );
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

List<MachOObjCProtocol> _readObjCProtocolsFromBytes(
  List<int> bytes, {
  required bool is64Bit,
  required List<MachOSegment> segments,
}) {
  final protocols = <MachOObjCProtocol>[];
  final pointerSize = is64Bit ? 8 : 4;
  final allSections = _allSections(segments).toList();
  final stringSections = _stringSections(segments).toList();

  for (final section in _objcProtocolReferenceSections(segments)) {
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
      final protocolAddress = _readPointerValue(
        sectionBytes,
        offset,
        allSections,
        is64Bit: is64Bit,
      );
      final name = _readObjCProtocolNameFromBytes(
        bytes,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        protocolAddress: protocolAddress,
      );
      if (name == null) continue;

      protocols.add(
        MachOObjCProtocol(
          name: name,
          sourceSection: section.displayName,
          protocolAddress: protocolAddress,
        ),
      );
      protocols.addAll(
        _readObjCInheritedProtocolsFromBytes(
          bytes,
          is64Bit: is64Bit,
          allSections: allSections,
          stringSections: stringSections,
          protocolAddress: protocolAddress,
          visitedProtocolAddresses: {protocolAddress},
        ),
      );
    }
  }

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
      final classAddress = _readPointerValue(
        sectionBytes,
        offset,
        allSections,
        is64Bit: is64Bit,
      );
      final metadata = _readObjCClassMetadataFromBytes(
        bytes,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        classAddress: classAddress,
      );
      if (metadata == null || metadata.protocolsAddress == 0) continue;

      protocols.addAll(
        _readObjCProtocolListFromBytes(
          bytes,
          is64Bit: is64Bit,
          allSections: allSections,
          stringSections: stringSections,
          protocolListAddress: metadata.protocolsAddress,
        ),
      );
    }
  }

  for (final section in _objcCategoryListSections(segments)) {
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
      final categoryAddress = _readPointerValue(
        sectionBytes,
        offset,
        allSections,
        is64Bit: is64Bit,
      );
      final metadata = _readObjCCategoryMetadataFromBytes(
        bytes,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        categoryAddress: categoryAddress,
      );
      if (metadata == null || metadata.protocolsAddress == 0) continue;

      protocols.addAll(
        _readObjCProtocolListFromBytes(
          bytes,
          is64Bit: is64Bit,
          allSections: allSections,
          stringSections: stringSections,
          protocolListAddress: metadata.protocolsAddress,
        ),
      );
    }
  }

  return protocols;
}

List<MachOObjCSelector> _readObjCSelectorsFromBytes(
  List<int> bytes, {
  required bool is64Bit,
  required List<MachOSegment> segments,
}) {
  final selectors = <MachOObjCSelector>[];
  final pointerSize = is64Bit ? 8 : 4;
  final allSections = _allSections(segments).toList();
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
      final targetAddress = _readPointerValue(
        sectionBytes,
        offset,
        allSections,
        is64Bit: is64Bit,
      );
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
  final protocolsAddress =
      _readPointerAtAddressFromFile(
        raf,
        fileOffset,
        availableLength,
        allSections,
        classRoAddress + (is64Bit ? 40 : 24),
        is64Bit: is64Bit,
      ) ??
      0;
  final ivarsAddress =
      _readPointerAtAddressFromFile(
        raf,
        fileOffset,
        availableLength,
        allSections,
        classRoAddress + (is64Bit ? 48 : 28),
        is64Bit: is64Bit,
      ) ??
      0;
  final basePropertiesAddress =
      _readPointerAtAddressFromFile(
        raf,
        fileOffset,
        availableLength,
        allSections,
        classRoAddress + (is64Bit ? 64 : 36),
        is64Bit: is64Bit,
      ) ??
      0;

  return _ObjCClassMetadata(
    name: name,
    classRoAddress: classRoAddress,
    baseMethodsAddress: baseMethodsAddress,
    protocolsAddress: protocolsAddress,
    ivarsAddress: ivarsAddress,
    basePropertiesAddress: basePropertiesAddress,
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

String? _readObjCProtocolNameFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required int protocolAddress,
}) {
  final nameAddress = _readPointerAtAddressFromFile(
    raf,
    fileOffset,
    availableLength,
    allSections,
    protocolAddress + (is64Bit ? 8 : 4),
    is64Bit: is64Bit,
  );
  if (nameAddress == null) return null;

  return _readCStringAtAddressFromFile(
    raf,
    fileOffset,
    availableLength,
    stringSections,
    nameAddress,
  );
}

String? _readObjCProtocolNameFromBytes(
  List<int> bytes, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required int protocolAddress,
}) {
  final nameAddress = _readPointerAtAddressFromBytes(
    bytes,
    allSections,
    protocolAddress + (is64Bit ? 8 : 4),
    is64Bit: is64Bit,
  );
  if (nameAddress == null) return null;

  return _readCStringAtAddressFromBytes(bytes, stringSections, nameAddress);
}

List<MachOObjCProtocol> _readObjCInheritedProtocolsFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required int protocolAddress,
  required Set<int> visitedProtocolAddresses,
}) {
  final pointerSize = is64Bit ? 8 : 4;
  final inheritedProtocolListAddress =
      _readPointerAtAddressFromFile(
        raf,
        fileOffset,
        availableLength,
        allSections,
        protocolAddress + 2 * pointerSize,
        is64Bit: is64Bit,
      ) ??
      0;
  if (inheritedProtocolListAddress == 0) return const [];

  return _readObjCProtocolListFromFile(
    raf,
    fileOffset,
    availableLength,
    is64Bit: is64Bit,
    allSections: allSections,
    stringSections: stringSections,
    protocolListAddress: inheritedProtocolListAddress,
    visitedProtocolAddresses: visitedProtocolAddresses,
  );
}

List<MachOObjCProtocol> _readObjCInheritedProtocolsFromBytes(
  List<int> bytes, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required int protocolAddress,
  required Set<int> visitedProtocolAddresses,
}) {
  final pointerSize = is64Bit ? 8 : 4;
  final inheritedProtocolListAddress =
      _readPointerAtAddressFromBytes(
        bytes,
        allSections,
        protocolAddress + 2 * pointerSize,
        is64Bit: is64Bit,
      ) ??
      0;
  if (inheritedProtocolListAddress == 0) return const [];

  return _readObjCProtocolListFromBytes(
    bytes,
    is64Bit: is64Bit,
    allSections: allSections,
    stringSections: stringSections,
    protocolListAddress: inheritedProtocolListAddress,
    visitedProtocolAddresses: visitedProtocolAddresses,
  );
}

List<MachOObjCProtocol> _readObjCProtocolListFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required int protocolListAddress,
  Set<int>? visitedProtocolAddresses,
}) {
  final section = _sectionContainingAddress(allSections, protocolListAddress);
  if (section == null || !_canReadSection(section, availableLength)) {
    return const [];
  }

  final pointerSize = is64Bit ? 8 : 4;
  final protocolCount = _readPointerAtAddressFromFile(
    raf,
    fileOffset,
    availableLength,
    allSections,
    protocolListAddress,
    is64Bit: is64Bit,
  );
  if (protocolCount == null ||
      !_canReadObjCProtocolList(pointerSize, protocolCount)) {
    return const [];
  }

  final protocols = <MachOObjCProtocol>[];
  final visited = visitedProtocolAddresses ?? <int>{};
  for (var i = 0; i < protocolCount; i += 1) {
    final entryAddress = protocolListAddress + pointerSize + i * pointerSize;
    final protocolAddress = _readPointerAtAddressFromFile(
      raf,
      fileOffset,
      availableLength,
      allSections,
      entryAddress,
      is64Bit: is64Bit,
    );
    if (protocolAddress == null || protocolAddress == 0) continue;
    if (!visited.add(protocolAddress)) continue;

    final name = _readObjCProtocolNameFromFile(
      raf,
      fileOffset,
      availableLength,
      is64Bit: is64Bit,
      allSections: allSections,
      stringSections: stringSections,
      protocolAddress: protocolAddress,
    );
    if (name == null) continue;

    protocols.add(
      MachOObjCProtocol(
        name: name,
        sourceSection: section.displayName,
        protocolAddress: protocolAddress,
      ),
    );

    final inheritedProtocolListAddress =
        _readPointerAtAddressFromFile(
          raf,
          fileOffset,
          availableLength,
          allSections,
          protocolAddress + 2 * pointerSize,
          is64Bit: is64Bit,
        ) ??
        0;
    if (inheritedProtocolListAddress != 0) {
      protocols.addAll(
        _readObjCProtocolListFromFile(
          raf,
          fileOffset,
          availableLength,
          is64Bit: is64Bit,
          allSections: allSections,
          stringSections: stringSections,
          protocolListAddress: inheritedProtocolListAddress,
          visitedProtocolAddresses: visited,
        ),
      );
    }
  }

  return protocols;
}

List<MachOObjCProtocol> _readObjCProtocolListFromBytes(
  List<int> bytes, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required int protocolListAddress,
  Set<int>? visitedProtocolAddresses,
}) {
  final section = _sectionContainingAddress(allSections, protocolListAddress);
  if (section == null || !_canReadSection(section, bytes.length)) {
    return const [];
  }

  final pointerSize = is64Bit ? 8 : 4;
  final protocolCount = _readPointerAtAddressFromBytes(
    bytes,
    allSections,
    protocolListAddress,
    is64Bit: is64Bit,
  );
  if (protocolCount == null ||
      !_canReadObjCProtocolList(pointerSize, protocolCount)) {
    return const [];
  }

  final protocols = <MachOObjCProtocol>[];
  final visited = visitedProtocolAddresses ?? <int>{};
  for (var i = 0; i < protocolCount; i += 1) {
    final entryAddress = protocolListAddress + pointerSize + i * pointerSize;
    final protocolAddress = _readPointerAtAddressFromBytes(
      bytes,
      allSections,
      entryAddress,
      is64Bit: is64Bit,
    );
    if (protocolAddress == null || protocolAddress == 0) continue;
    if (!visited.add(protocolAddress)) continue;

    final name = _readObjCProtocolNameFromBytes(
      bytes,
      is64Bit: is64Bit,
      allSections: allSections,
      stringSections: stringSections,
      protocolAddress: protocolAddress,
    );
    if (name == null) continue;

    protocols.add(
      MachOObjCProtocol(
        name: name,
        sourceSection: section.displayName,
        protocolAddress: protocolAddress,
      ),
    );

    final inheritedProtocolListAddress =
        _readPointerAtAddressFromBytes(
          bytes,
          allSections,
          protocolAddress + 2 * pointerSize,
          is64Bit: is64Bit,
        ) ??
        0;
    if (inheritedProtocolListAddress != 0) {
      protocols.addAll(
        _readObjCProtocolListFromBytes(
          bytes,
          is64Bit: is64Bit,
          allSections: allSections,
          stringSections: stringSections,
          protocolListAddress: inheritedProtocolListAddress,
          visitedProtocolAddresses: visited,
        ),
      );
    }
  }

  return protocols;
}

List<MachOObjCMethod> _readObjCProtocolListMethodsFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required int protocolListAddress,
  Set<int>? visitedProtocolAddresses,
}) {
  final pointerSize = is64Bit ? 8 : 4;
  final protocolCount = _readPointerAtAddressFromFile(
    raf,
    fileOffset,
    availableLength,
    allSections,
    protocolListAddress,
    is64Bit: is64Bit,
  );
  if (protocolCount == null ||
      !_canReadObjCProtocolList(pointerSize, protocolCount)) {
    return const [];
  }

  final methods = <MachOObjCMethod>[];
  final visited = visitedProtocolAddresses ?? <int>{};
  for (var i = 0; i < protocolCount; i += 1) {
    final entryAddress = protocolListAddress + pointerSize + i * pointerSize;
    final protocolAddress = _readPointerAtAddressFromFile(
      raf,
      fileOffset,
      availableLength,
      allSections,
      entryAddress,
      is64Bit: is64Bit,
    );
    if (protocolAddress == null || protocolAddress == 0) continue;
    if (!visited.add(protocolAddress)) continue;

    methods.addAll(
      _readObjCProtocolMethodsFromFile(
        raf,
        fileOffset,
        availableLength,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        protocolAddress: protocolAddress,
        visitedProtocolAddresses: visited,
      ),
    );
  }

  return methods;
}

List<MachOObjCMethod> _readObjCProtocolMethodsFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required int protocolAddress,
  Set<int>? visitedProtocolAddresses,
}) {
  final pointerSize = is64Bit ? 8 : 4;
  final visited = visitedProtocolAddresses ?? <int>{};
  visited.add(protocolAddress);
  final protocolName = _readObjCProtocolNameFromFile(
    raf,
    fileOffset,
    availableLength,
    is64Bit: is64Bit,
    allSections: allSections,
    stringSections: stringSections,
    protocolAddress: protocolAddress,
  );
  if (protocolName == null) return const [];

  final methods = <MachOObjCMethod>[];
  for (final methodListOffset
      in is64Bit ? const [24, 32, 40, 48] : const [12, 16, 20, 24]) {
    final methodListAddress =
        _readPointerAtAddressFromFile(
          raf,
          fileOffset,
          availableLength,
          allSections,
          protocolAddress + methodListOffset,
          is64Bit: is64Bit,
        ) ??
        0;
    if (methodListAddress == 0) continue;

    methods.addAll(
      _readObjCMethodListsFromFile(
        raf,
        fileOffset,
        availableLength,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        className: protocolName,
        methodListAddress: methodListAddress,
      ),
    );
  }

  final inheritedProtocolListAddress =
      _readPointerAtAddressFromFile(
        raf,
        fileOffset,
        availableLength,
        allSections,
        protocolAddress + 2 * pointerSize,
        is64Bit: is64Bit,
      ) ??
      0;
  if (inheritedProtocolListAddress != 0) {
    methods.addAll(
      _readObjCProtocolListMethodsFromFile(
        raf,
        fileOffset,
        availableLength,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        protocolListAddress: inheritedProtocolListAddress,
        visitedProtocolAddresses: visited,
      ),
    );
  }

  return methods;
}

List<MachOObjCMethod> _readObjCProtocolListMethodsFromBytes(
  List<int> bytes, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required int protocolListAddress,
  Set<int>? visitedProtocolAddresses,
}) {
  final pointerSize = is64Bit ? 8 : 4;
  final protocolCount = _readPointerAtAddressFromBytes(
    bytes,
    allSections,
    protocolListAddress,
    is64Bit: is64Bit,
  );
  if (protocolCount == null ||
      !_canReadObjCProtocolList(pointerSize, protocolCount)) {
    return const [];
  }

  final methods = <MachOObjCMethod>[];
  final visited = visitedProtocolAddresses ?? <int>{};
  for (var i = 0; i < protocolCount; i += 1) {
    final entryAddress = protocolListAddress + pointerSize + i * pointerSize;
    final protocolAddress = _readPointerAtAddressFromBytes(
      bytes,
      allSections,
      entryAddress,
      is64Bit: is64Bit,
    );
    if (protocolAddress == null || protocolAddress == 0) continue;
    if (!visited.add(protocolAddress)) continue;

    methods.addAll(
      _readObjCProtocolMethodsFromBytes(
        bytes,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        protocolAddress: protocolAddress,
        visitedProtocolAddresses: visited,
      ),
    );
  }

  return methods;
}

List<MachOObjCMethod> _readObjCProtocolMethodsFromBytes(
  List<int> bytes, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required int protocolAddress,
  Set<int>? visitedProtocolAddresses,
}) {
  final pointerSize = is64Bit ? 8 : 4;
  final visited = visitedProtocolAddresses ?? <int>{};
  visited.add(protocolAddress);
  final protocolName = _readObjCProtocolNameFromBytes(
    bytes,
    is64Bit: is64Bit,
    allSections: allSections,
    stringSections: stringSections,
    protocolAddress: protocolAddress,
  );
  if (protocolName == null) return const [];

  final methods = <MachOObjCMethod>[];
  for (final methodListOffset
      in is64Bit ? const [24, 32, 40, 48] : const [12, 16, 20, 24]) {
    final methodListAddress =
        _readPointerAtAddressFromBytes(
          bytes,
          allSections,
          protocolAddress + methodListOffset,
          is64Bit: is64Bit,
        ) ??
        0;
    if (methodListAddress == 0) continue;

    methods.addAll(
      _readObjCMethodListsFromBytes(
        bytes,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        className: protocolName,
        methodListAddress: methodListAddress,
      ),
    );
  }

  final inheritedProtocolListAddress =
      _readPointerAtAddressFromBytes(
        bytes,
        allSections,
        protocolAddress + 2 * pointerSize,
        is64Bit: is64Bit,
      ) ??
      0;
  if (inheritedProtocolListAddress != 0) {
    methods.addAll(
      _readObjCProtocolListMethodsFromBytes(
        bytes,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        protocolListAddress: inheritedProtocolListAddress,
        visitedProtocolAddresses: visited,
      ),
    );
  }

  return methods;
}

List<MachOObjCIvar> _readObjCIvarListFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required String className,
  required int ivarListAddress,
}) {
  final section = _sectionContainingAddress(allSections, ivarListAddress);
  if (section == null || !_canReadSection(section, availableLength)) {
    return const [];
  }

  final header = _readBytesAtAddressFromFile(
    raf,
    fileOffset,
    availableLength,
    allSections,
    ivarListAddress,
    8,
  );
  if (header == null) return const [];

  final pointerSize = is64Bit ? 8 : 4;
  final entrySize = _readU32(header, 0);
  final entryCount = _readU32(header, 4);
  if (!_canReadObjCIvarList(pointerSize, entrySize, entryCount)) {
    return const [];
  }

  final ivars = <MachOObjCIvar>[];
  for (var i = 0; i < entryCount; i += 1) {
    final entryAddress = ivarListAddress + 8 + i * entrySize;
    final nameAddress = _readPointerAtAddressFromFile(
      raf,
      fileOffset,
      availableLength,
      allSections,
      entryAddress + pointerSize,
      is64Bit: is64Bit,
    );
    final typeAddress = _readPointerAtAddressFromFile(
      raf,
      fileOffset,
      availableLength,
      allSections,
      entryAddress + 2 * pointerSize,
      is64Bit: is64Bit,
    );
    if (nameAddress == null || typeAddress == null) continue;

    final name = _readCStringAtAddressFromFile(
      raf,
      fileOffset,
      availableLength,
      stringSections,
      nameAddress,
    );
    final typeEncoding = _readCStringAtAddressFromFile(
      raf,
      fileOffset,
      availableLength,
      stringSections,
      typeAddress,
    );
    if (name == null || typeEncoding == null) continue;

    ivars.add(
      MachOObjCIvar(
        name: name,
        typeEncoding: typeEncoding,
        className: className,
        sourceSection: section.displayName,
        ivarListAddress: ivarListAddress,
      ),
    );
  }

  return ivars;
}

List<MachOObjCIvar> _readObjCIvarListFromBytes(
  List<int> bytes, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required String className,
  required int ivarListAddress,
}) {
  final section = _sectionContainingAddress(allSections, ivarListAddress);
  if (section == null || !_canReadSection(section, bytes.length)) {
    return const [];
  }

  final header = _readBytesAtAddressFromBytes(
    bytes,
    allSections,
    ivarListAddress,
    8,
  );
  if (header == null) return const [];

  final pointerSize = is64Bit ? 8 : 4;
  final entrySize = _readU32(header, 0);
  final entryCount = _readU32(header, 4);
  if (!_canReadObjCIvarList(pointerSize, entrySize, entryCount)) {
    return const [];
  }

  final ivars = <MachOObjCIvar>[];
  for (var i = 0; i < entryCount; i += 1) {
    final entryAddress = ivarListAddress + 8 + i * entrySize;
    final nameAddress = _readPointerAtAddressFromBytes(
      bytes,
      allSections,
      entryAddress + pointerSize,
      is64Bit: is64Bit,
    );
    final typeAddress = _readPointerAtAddressFromBytes(
      bytes,
      allSections,
      entryAddress + 2 * pointerSize,
      is64Bit: is64Bit,
    );
    if (nameAddress == null || typeAddress == null) continue;

    final name = _readCStringAtAddressFromBytes(
      bytes,
      stringSections,
      nameAddress,
    );
    final typeEncoding = _readCStringAtAddressFromBytes(
      bytes,
      stringSections,
      typeAddress,
    );
    if (name == null || typeEncoding == null) continue;

    ivars.add(
      MachOObjCIvar(
        name: name,
        typeEncoding: typeEncoding,
        className: className,
        sourceSection: section.displayName,
        ivarListAddress: ivarListAddress,
      ),
    );
  }

  return ivars;
}

List<MachOObjCProperty> _readObjCPropertyListFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required String className,
  required int propertyListAddress,
}) {
  final section = _sectionContainingAddress(allSections, propertyListAddress);
  if (section == null || !_canReadSection(section, availableLength)) {
    return const [];
  }

  final header = _readBytesAtAddressFromFile(
    raf,
    fileOffset,
    availableLength,
    allSections,
    propertyListAddress,
    8,
  );
  if (header == null) return const [];

  final pointerSize = is64Bit ? 8 : 4;
  final entrySize = _readU32(header, 0);
  final entryCount = _readU32(header, 4);
  if (!_canReadObjCPropertyList(pointerSize, entrySize, entryCount)) {
    return const [];
  }

  final properties = <MachOObjCProperty>[];
  for (var i = 0; i < entryCount; i += 1) {
    final entryAddress = propertyListAddress + 8 + i * entrySize;
    final nameAddress = _readPointerAtAddressFromFile(
      raf,
      fileOffset,
      availableLength,
      allSections,
      entryAddress,
      is64Bit: is64Bit,
    );
    final attributesAddress = _readPointerAtAddressFromFile(
      raf,
      fileOffset,
      availableLength,
      allSections,
      entryAddress + pointerSize,
      is64Bit: is64Bit,
    );
    if (nameAddress == null || attributesAddress == null) continue;

    final name = _readCStringAtAddressFromFile(
      raf,
      fileOffset,
      availableLength,
      stringSections,
      nameAddress,
    );
    final attributes = _readCStringAtAddressFromFile(
      raf,
      fileOffset,
      availableLength,
      stringSections,
      attributesAddress,
    );
    if (name == null || attributes == null) continue;

    properties.add(
      MachOObjCProperty(
        name: name,
        attributes: attributes,
        className: className,
        sourceSection: section.displayName,
        propertyListAddress: propertyListAddress,
      ),
    );
  }

  return properties;
}

List<MachOObjCProperty> _readObjCProtocolListPropertiesFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required int protocolListAddress,
  Set<int>? visitedProtocolAddresses,
}) {
  final pointerSize = is64Bit ? 8 : 4;
  final protocolCount = _readPointerAtAddressFromFile(
    raf,
    fileOffset,
    availableLength,
    allSections,
    protocolListAddress,
    is64Bit: is64Bit,
  );
  if (protocolCount == null ||
      !_canReadObjCProtocolList(pointerSize, protocolCount)) {
    return const [];
  }

  final properties = <MachOObjCProperty>[];
  final visited = visitedProtocolAddresses ?? <int>{};
  for (var i = 0; i < protocolCount; i += 1) {
    final entryAddress = protocolListAddress + pointerSize + i * pointerSize;
    final protocolAddress = _readPointerAtAddressFromFile(
      raf,
      fileOffset,
      availableLength,
      allSections,
      entryAddress,
      is64Bit: is64Bit,
    );
    if (protocolAddress == null || protocolAddress == 0) continue;
    if (!visited.add(protocolAddress)) continue;

    properties.addAll(
      _readObjCProtocolPropertiesFromFile(
        raf,
        fileOffset,
        availableLength,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        protocolAddress: protocolAddress,
        visitedProtocolAddresses: visited,
      ),
    );
  }

  return properties;
}

List<MachOObjCProperty> _readObjCProtocolPropertiesFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required int protocolAddress,
  Set<int>? visitedProtocolAddresses,
}) {
  final pointerSize = is64Bit ? 8 : 4;
  final visited = visitedProtocolAddresses ?? <int>{};
  visited.add(protocolAddress);
  final protocolName = _readObjCProtocolNameFromFile(
    raf,
    fileOffset,
    availableLength,
    is64Bit: is64Bit,
    allSections: allSections,
    stringSections: stringSections,
    protocolAddress: protocolAddress,
  );
  if (protocolName == null) return const [];

  final instancePropertyListAddress = _readPointerAtAddressFromFile(
    raf,
    fileOffset,
    availableLength,
    allSections,
    protocolAddress + (is64Bit ? 56 : 28),
    is64Bit: is64Bit,
  );
  final classPropertyListAddress = _readObjCProtocolClassPropertiesFromFile(
    raf,
    fileOffset,
    availableLength,
    is64Bit: is64Bit,
    allSections: allSections,
    protocolAddress: protocolAddress,
  );

  final propertyListAddresses = [
    if (instancePropertyListAddress != null && instancePropertyListAddress != 0)
      instancePropertyListAddress,
    if (classPropertyListAddress != 0) classPropertyListAddress,
  ];
  final properties = [
    for (final propertyListAddress in propertyListAddresses)
      ..._readObjCPropertyListFromFile(
        raf,
        fileOffset,
        availableLength,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        className: protocolName,
        propertyListAddress: propertyListAddress,
      ),
  ];

  final inheritedProtocolListAddress =
      _readPointerAtAddressFromFile(
        raf,
        fileOffset,
        availableLength,
        allSections,
        protocolAddress + 2 * pointerSize,
        is64Bit: is64Bit,
      ) ??
      0;
  if (inheritedProtocolListAddress != 0) {
    properties.addAll(
      _readObjCProtocolListPropertiesFromFile(
        raf,
        fileOffset,
        availableLength,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        protocolListAddress: inheritedProtocolListAddress,
        visitedProtocolAddresses: visited,
      ),
    );
  }

  return properties;
}

int _readObjCProtocolClassPropertiesFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required int protocolAddress,
}) {
  final pointerSize = is64Bit ? 8 : 4;
  final sizeOffset = is64Bit ? 64 : 32;
  final classPropertiesOffset = is64Bit ? 88 : 48;
  final sizeBytes = _readBytesAtAddressFromFile(
    raf,
    fileOffset,
    availableLength,
    allSections,
    protocolAddress + sizeOffset,
    4,
  );
  if (sizeBytes == null) return 0;

  final protocolSize = _readU32(sizeBytes, 0);
  if (protocolSize < classPropertiesOffset + pointerSize) return 0;

  return _readPointerAtAddressFromFile(
        raf,
        fileOffset,
        availableLength,
        allSections,
        protocolAddress + classPropertiesOffset,
        is64Bit: is64Bit,
      ) ??
      0;
}

List<MachOObjCProperty> _readObjCPropertyListFromBytes(
  List<int> bytes, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required String className,
  required int propertyListAddress,
}) {
  final section = _sectionContainingAddress(allSections, propertyListAddress);
  if (section == null || !_canReadSection(section, bytes.length)) {
    return const [];
  }

  final header = _readBytesAtAddressFromBytes(
    bytes,
    allSections,
    propertyListAddress,
    8,
  );
  if (header == null) return const [];

  final pointerSize = is64Bit ? 8 : 4;
  final entrySize = _readU32(header, 0);
  final entryCount = _readU32(header, 4);
  if (!_canReadObjCPropertyList(pointerSize, entrySize, entryCount)) {
    return const [];
  }

  final properties = <MachOObjCProperty>[];
  for (var i = 0; i < entryCount; i += 1) {
    final entryAddress = propertyListAddress + 8 + i * entrySize;
    final nameAddress = _readPointerAtAddressFromBytes(
      bytes,
      allSections,
      entryAddress,
      is64Bit: is64Bit,
    );
    final attributesAddress = _readPointerAtAddressFromBytes(
      bytes,
      allSections,
      entryAddress + pointerSize,
      is64Bit: is64Bit,
    );
    if (nameAddress == null || attributesAddress == null) continue;

    final name = _readCStringAtAddressFromBytes(
      bytes,
      stringSections,
      nameAddress,
    );
    final attributes = _readCStringAtAddressFromBytes(
      bytes,
      stringSections,
      attributesAddress,
    );
    if (name == null || attributes == null) continue;

    properties.add(
      MachOObjCProperty(
        name: name,
        attributes: attributes,
        className: className,
        sourceSection: section.displayName,
        propertyListAddress: propertyListAddress,
      ),
    );
  }

  return properties;
}

List<MachOObjCProperty> _readObjCProtocolListPropertiesFromBytes(
  List<int> bytes, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required int protocolListAddress,
  Set<int>? visitedProtocolAddresses,
}) {
  final pointerSize = is64Bit ? 8 : 4;
  final protocolCount = _readPointerAtAddressFromBytes(
    bytes,
    allSections,
    protocolListAddress,
    is64Bit: is64Bit,
  );
  if (protocolCount == null ||
      !_canReadObjCProtocolList(pointerSize, protocolCount)) {
    return const [];
  }

  final properties = <MachOObjCProperty>[];
  final visited = visitedProtocolAddresses ?? <int>{};
  for (var i = 0; i < protocolCount; i += 1) {
    final entryAddress = protocolListAddress + pointerSize + i * pointerSize;
    final protocolAddress = _readPointerAtAddressFromBytes(
      bytes,
      allSections,
      entryAddress,
      is64Bit: is64Bit,
    );
    if (protocolAddress == null || protocolAddress == 0) continue;
    if (!visited.add(protocolAddress)) continue;

    properties.addAll(
      _readObjCProtocolPropertiesFromBytes(
        bytes,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        protocolAddress: protocolAddress,
        visitedProtocolAddresses: visited,
      ),
    );
  }

  return properties;
}

List<MachOObjCProperty> _readObjCProtocolPropertiesFromBytes(
  List<int> bytes, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required int protocolAddress,
  Set<int>? visitedProtocolAddresses,
}) {
  final pointerSize = is64Bit ? 8 : 4;
  final visited = visitedProtocolAddresses ?? <int>{};
  visited.add(protocolAddress);
  final protocolName = _readObjCProtocolNameFromBytes(
    bytes,
    is64Bit: is64Bit,
    allSections: allSections,
    stringSections: stringSections,
    protocolAddress: protocolAddress,
  );
  if (protocolName == null) return const [];

  final instancePropertyListAddress = _readPointerAtAddressFromBytes(
    bytes,
    allSections,
    protocolAddress + (is64Bit ? 56 : 28),
    is64Bit: is64Bit,
  );
  final classPropertyListAddress = _readObjCProtocolClassPropertiesFromBytes(
    bytes,
    is64Bit: is64Bit,
    allSections: allSections,
    protocolAddress: protocolAddress,
  );

  final propertyListAddresses = [
    if (instancePropertyListAddress != null && instancePropertyListAddress != 0)
      instancePropertyListAddress,
    if (classPropertyListAddress != 0) classPropertyListAddress,
  ];
  final properties = [
    for (final propertyListAddress in propertyListAddresses)
      ..._readObjCPropertyListFromBytes(
        bytes,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        className: protocolName,
        propertyListAddress: propertyListAddress,
      ),
  ];

  final inheritedProtocolListAddress =
      _readPointerAtAddressFromBytes(
        bytes,
        allSections,
        protocolAddress + 2 * pointerSize,
        is64Bit: is64Bit,
      ) ??
      0;
  if (inheritedProtocolListAddress != 0) {
    properties.addAll(
      _readObjCProtocolListPropertiesFromBytes(
        bytes,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        protocolListAddress: inheritedProtocolListAddress,
        visitedProtocolAddresses: visited,
      ),
    );
  }

  return properties;
}

int _readObjCProtocolClassPropertiesFromBytes(
  List<int> bytes, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required int protocolAddress,
}) {
  final pointerSize = is64Bit ? 8 : 4;
  final sizeOffset = is64Bit ? 64 : 32;
  final classPropertiesOffset = is64Bit ? 88 : 48;
  final sizeBytes = _readBytesAtAddressFromBytes(
    bytes,
    allSections,
    protocolAddress + sizeOffset,
    4,
  );
  if (sizeBytes == null) return 0;

  final protocolSize = _readU32(sizeBytes, 0);
  if (protocolSize < classPropertiesOffset + pointerSize) return 0;

  return _readPointerAtAddressFromBytes(
        bytes,
        allSections,
        protocolAddress + classPropertiesOffset,
        is64Bit: is64Bit,
      ) ??
      0;
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
  final protocolsAddress =
      _readPointerAtAddressFromBytes(
        bytes,
        allSections,
        classRoAddress + (is64Bit ? 40 : 24),
        is64Bit: is64Bit,
      ) ??
      0;
  final ivarsAddress =
      _readPointerAtAddressFromBytes(
        bytes,
        allSections,
        classRoAddress + (is64Bit ? 48 : 28),
        is64Bit: is64Bit,
      ) ??
      0;
  final basePropertiesAddress =
      _readPointerAtAddressFromBytes(
        bytes,
        allSections,
        classRoAddress + (is64Bit ? 64 : 36),
        is64Bit: is64Bit,
      ) ??
      0;

  return _ObjCClassMetadata(
    name: name,
    classRoAddress: classRoAddress,
    baseMethodsAddress: baseMethodsAddress,
    protocolsAddress: protocolsAddress,
    ivarsAddress: ivarsAddress,
    basePropertiesAddress: basePropertiesAddress,
  );
}

_ObjCCategoryMetadata? _readObjCCategoryMetadataFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required int categoryAddress,
}) {
  final pointerSize = is64Bit ? 8 : 4;
  final nameAddress = _readPointerAtAddressFromFile(
    raf,
    fileOffset,
    availableLength,
    allSections,
    categoryAddress,
    is64Bit: is64Bit,
  );
  final classAddress = _readPointerAtAddressFromFile(
    raf,
    fileOffset,
    availableLength,
    allSections,
    categoryAddress + pointerSize,
    is64Bit: is64Bit,
  );
  if (nameAddress == null || classAddress == null) return null;

  final categoryName = _readCStringAtAddressFromFile(
    raf,
    fileOffset,
    availableLength,
    stringSections,
    nameAddress,
  );
  final className = _readObjCClassNameFromFile(
    raf,
    fileOffset,
    availableLength,
    is64Bit: is64Bit,
    allSections: allSections,
    stringSections: stringSections,
    classAddress: classAddress,
  );
  final ownerName = className ?? categoryName;
  if (ownerName == null) return null;

  return _ObjCCategoryMetadata(
    ownerName: ownerName,
    instanceMethodsAddress:
        _readPointerAtAddressFromFile(
          raf,
          fileOffset,
          availableLength,
          allSections,
          categoryAddress + 2 * pointerSize,
          is64Bit: is64Bit,
        ) ??
        0,
    classMethodsAddress:
        _readPointerAtAddressFromFile(
          raf,
          fileOffset,
          availableLength,
          allSections,
          categoryAddress + 3 * pointerSize,
          is64Bit: is64Bit,
        ) ??
        0,
    protocolsAddress:
        _readPointerAtAddressFromFile(
          raf,
          fileOffset,
          availableLength,
          allSections,
          categoryAddress + 4 * pointerSize,
          is64Bit: is64Bit,
        ) ??
        0,
    instancePropertiesAddress:
        _readPointerAtAddressFromFile(
          raf,
          fileOffset,
          availableLength,
          allSections,
          categoryAddress + 5 * pointerSize,
          is64Bit: is64Bit,
        ) ??
        0,
    classPropertiesAddress:
        _readPointerAtAddressFromFile(
          raf,
          fileOffset,
          availableLength,
          allSections,
          categoryAddress + 6 * pointerSize,
          is64Bit: is64Bit,
        ) ??
        0,
  );
}

_ObjCCategoryMetadata? _readObjCCategoryMetadataFromBytes(
  List<int> bytes, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required int categoryAddress,
}) {
  final pointerSize = is64Bit ? 8 : 4;
  final nameAddress = _readPointerAtAddressFromBytes(
    bytes,
    allSections,
    categoryAddress,
    is64Bit: is64Bit,
  );
  final classAddress = _readPointerAtAddressFromBytes(
    bytes,
    allSections,
    categoryAddress + pointerSize,
    is64Bit: is64Bit,
  );
  if (nameAddress == null || classAddress == null) return null;

  final categoryName = _readCStringAtAddressFromBytes(
    bytes,
    stringSections,
    nameAddress,
  );
  final className = _readObjCClassNameFromBytes(
    bytes,
    is64Bit: is64Bit,
    allSections: allSections,
    stringSections: stringSections,
    classAddress: classAddress,
  );
  final ownerName = className ?? categoryName;
  if (ownerName == null) return null;

  return _ObjCCategoryMetadata(
    ownerName: ownerName,
    instanceMethodsAddress:
        _readPointerAtAddressFromBytes(
          bytes,
          allSections,
          categoryAddress + 2 * pointerSize,
          is64Bit: is64Bit,
        ) ??
        0,
    classMethodsAddress:
        _readPointerAtAddressFromBytes(
          bytes,
          allSections,
          categoryAddress + 3 * pointerSize,
          is64Bit: is64Bit,
        ) ??
        0,
    protocolsAddress:
        _readPointerAtAddressFromBytes(
          bytes,
          allSections,
          categoryAddress + 4 * pointerSize,
          is64Bit: is64Bit,
        ) ??
        0,
    instancePropertiesAddress:
        _readPointerAtAddressFromBytes(
          bytes,
          allSections,
          categoryAddress + 5 * pointerSize,
          is64Bit: is64Bit,
        ) ??
        0,
    classPropertiesAddress:
        _readPointerAtAddressFromBytes(
          bytes,
          allSections,
          categoryAddress + 6 * pointerSize,
          is64Bit: is64Bit,
        ) ??
        0,
  );
}

List<MachOObjCMethod> _readObjCCategoryMethodListsFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required _ObjCCategoryMetadata metadata,
}) {
  final methods = <MachOObjCMethod>[];
  for (final methodListAddress in [
    metadata.instanceMethodsAddress,
    metadata.classMethodsAddress,
  ]) {
    if (methodListAddress == 0) continue;
    methods.addAll(
      _readObjCMethodListsFromFile(
        raf,
        fileOffset,
        availableLength,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        className: metadata.ownerName,
        methodListAddress: methodListAddress,
      ),
    );
  }
  return methods;
}

List<MachOObjCMethod> _readObjCCategoryMethodListsFromBytes(
  List<int> bytes, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required _ObjCCategoryMetadata metadata,
}) {
  final methods = <MachOObjCMethod>[];
  for (final methodListAddress in [
    metadata.instanceMethodsAddress,
    metadata.classMethodsAddress,
  ]) {
    if (methodListAddress == 0) continue;
    methods.addAll(
      _readObjCMethodListsFromBytes(
        bytes,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        className: metadata.ownerName,
        methodListAddress: methodListAddress,
      ),
    );
  }
  return methods;
}

List<MachOObjCMethod> _readObjCMethodListsFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required String className,
  required int methodListAddress,
}) {
  if ((methodListAddress & _objcRelativeMethodListsFlag) != 0) {
    return _readRelativeObjCMethodListsFromFile(
      raf,
      fileOffset,
      availableLength,
      is64Bit: is64Bit,
      allSections: allSections,
      stringSections: stringSections,
      className: className,
      listListAddress: methodListAddress & ~_objcRelativeMethodListsFlag,
    );
  }

  return _readObjCMethodListFromFile(
    raf,
    fileOffset,
    availableLength,
    is64Bit: is64Bit,
    allSections: allSections,
    stringSections: stringSections,
    className: className,
    methodListAddress: methodListAddress,
  );
}

List<MachOObjCMethod> _readObjCMethodListsFromBytes(
  List<int> bytes, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required String className,
  required int methodListAddress,
}) {
  if ((methodListAddress & _objcRelativeMethodListsFlag) != 0) {
    return _readRelativeObjCMethodListsFromBytes(
      bytes,
      is64Bit: is64Bit,
      allSections: allSections,
      stringSections: stringSections,
      className: className,
      listListAddress: methodListAddress & ~_objcRelativeMethodListsFlag,
    );
  }

  return _readObjCMethodListFromBytes(
    bytes,
    is64Bit: is64Bit,
    allSections: allSections,
    stringSections: stringSections,
    className: className,
    methodListAddress: methodListAddress,
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

List<MachOObjCMethod> _readRelativeObjCMethodListsFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required String className,
  required int listListAddress,
}) {
  final methods = <MachOObjCMethod>[];
  final header = _readBytesAtAddressFromFile(
    raf,
    fileOffset,
    availableLength,
    allSections,
    listListAddress,
    8,
  );
  if (header == null) return methods;

  final entrySize = _readU32(header, 0);
  final entryCount = _readU32(header, 4);
  if (!_canReadRelativeObjCMethodListList(entrySize, entryCount)) {
    return methods;
  }

  for (var i = 0; i < entryCount; i += 1) {
    final entryAddress = listListAddress + 8 + i * entrySize;
    final entry = _readBytesAtAddressFromFile(
      raf,
      fileOffset,
      availableLength,
      allSections,
      entryAddress,
      8,
    );
    if (entry == null) continue;

    final rawEntry = _readU64(entry, 0);
    final imageIndex = rawEntry & 0xffff;
    if (imageIndex != 0) continue;

    final methodListAddress = entryAddress + _signExtend(rawEntry >> 16, 48);
    methods.addAll(
      _readObjCMethodListFromFile(
        raf,
        fileOffset,
        availableLength,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        className: className,
        methodListAddress: methodListAddress,
      ),
    );
  }

  return methods;
}

List<MachOObjCMethod> _readRelativeObjCMethodListsFromBytes(
  List<int> bytes, {
  required bool is64Bit,
  required List<MachOSection> allSections,
  required List<MachOSection> stringSections,
  required String className,
  required int listListAddress,
}) {
  final methods = <MachOObjCMethod>[];
  final header = _readBytesAtAddressFromBytes(
    bytes,
    allSections,
    listListAddress,
    8,
  );
  if (header == null) return methods;

  final entrySize = _readU32(header, 0);
  final entryCount = _readU32(header, 4);
  if (!_canReadRelativeObjCMethodListList(entrySize, entryCount)) {
    return methods;
  }

  for (var i = 0; i < entryCount; i += 1) {
    final entryAddress = listListAddress + 8 + i * entrySize;
    final entry = _readBytesAtAddressFromBytes(
      bytes,
      allSections,
      entryAddress,
      8,
    );
    if (entry == null) continue;

    final rawEntry = _readU64(entry, 0);
    final imageIndex = rawEntry & 0xffff;
    if (imageIndex != 0) continue;

    final methodListAddress = entryAddress + _signExtend(rawEntry >> 16, 48);
    methods.addAll(
      _readObjCMethodListFromBytes(
        bytes,
        is64Bit: is64Bit,
        allSections: allSections,
        stringSections: stringSections,
        className: className,
        methodListAddress: methodListAddress,
      ),
    );
  }

  return methods;
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

String? _readSwiftTypeNameFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength,
  List<MachOSection> allSections,
  int descriptorAddress,
) {
  return _readSwiftContextDescriptorNameFromFile(
    raf,
    fileOffset,
    availableLength,
    allSections,
    descriptorAddress,
  );
}

String? _readSwiftTypeNameFromBytes(
  List<int> bytes,
  List<MachOSection> allSections,
  int descriptorAddress,
) {
  return _readSwiftContextDescriptorNameFromBytes(
    bytes,
    allSections,
    descriptorAddress,
  );
}

String? _readSwiftProtocolNameFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength,
  List<MachOSection> allSections,
  int descriptorAddress,
) {
  return _readSwiftContextDescriptorNameFromFile(
    raf,
    fileOffset,
    availableLength,
    allSections,
    descriptorAddress,
  );
}

String? _readSwiftProtocolNameFromBytes(
  List<int> bytes,
  List<MachOSection> allSections,
  int descriptorAddress,
) {
  return _readSwiftContextDescriptorNameFromBytes(
    bytes,
    allSections,
    descriptorAddress,
  );
}

MachOSwiftProtocolConformance? _readSwiftProtocolConformanceFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength,
  List<MachOSection> allSections,
  String sourceSection,
  int descriptorAddress,
) {
  final descriptorPrefix = _readBytesAtAddressFromFile(
    raf,
    fileOffset,
    availableLength,
    allSections,
    descriptorAddress,
    8,
  );
  if (descriptorPrefix == null) return null;

  final protocolDescriptorAddress =
      descriptorAddress + _readI32(descriptorPrefix, 0);
  final typeDescriptorAddress =
      descriptorAddress + 4 + _readI32(descriptorPrefix, 4);
  final protocolName = _readSwiftContextDescriptorNameFromFile(
    raf,
    fileOffset,
    availableLength,
    allSections,
    protocolDescriptorAddress,
  );
  final typeName = _readSwiftContextDescriptorNameFromFile(
    raf,
    fileOffset,
    availableLength,
    allSections,
    typeDescriptorAddress,
  );
  if (protocolName == null || typeName == null) return null;

  return MachOSwiftProtocolConformance(
    typeName: typeName,
    protocolName: protocolName,
    sourceSection: sourceSection,
    descriptorAddress: descriptorAddress,
  );
}

MachOSwiftProtocolConformance? _readSwiftProtocolConformanceFromBytes(
  List<int> bytes,
  List<MachOSection> allSections,
  String sourceSection,
  int descriptorAddress,
) {
  final descriptorPrefix = _readBytesAtAddressFromBytes(
    bytes,
    allSections,
    descriptorAddress,
    8,
  );
  if (descriptorPrefix == null) return null;

  final protocolDescriptorAddress =
      descriptorAddress + _readI32(descriptorPrefix, 0);
  final typeDescriptorAddress =
      descriptorAddress + 4 + _readI32(descriptorPrefix, 4);
  final protocolName = _readSwiftContextDescriptorNameFromBytes(
    bytes,
    allSections,
    protocolDescriptorAddress,
  );
  final typeName = _readSwiftContextDescriptorNameFromBytes(
    bytes,
    allSections,
    typeDescriptorAddress,
  );
  if (protocolName == null || typeName == null) return null;

  return MachOSwiftProtocolConformance(
    typeName: typeName,
    protocolName: protocolName,
    sourceSection: sourceSection,
    descriptorAddress: descriptorAddress,
  );
}

String? _readSwiftContextDescriptorNameFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength,
  List<MachOSection> allSections,
  int descriptorAddress,
) {
  final descriptorPrefix = _readBytesAtAddressFromFile(
    raf,
    fileOffset,
    availableLength,
    allSections,
    descriptorAddress,
    12,
  );
  if (descriptorPrefix == null) return null;

  final nameAddress = descriptorAddress + 8 + _readI32(descriptorPrefix, 8);
  final name = _readCStringAtAddressFromFile(
    raf,
    fileOffset,
    availableLength,
    allSections,
    nameAddress,
  );
  return _isPlausibleSwiftTypeName(name) ? name : null;
}

String? _readSwiftContextDescriptorNameFromBytes(
  List<int> bytes,
  List<MachOSection> allSections,
  int descriptorAddress,
) {
  final descriptorPrefix = _readBytesAtAddressFromBytes(
    bytes,
    allSections,
    descriptorAddress,
    12,
  );
  if (descriptorPrefix == null) return null;

  final nameAddress = descriptorAddress + 8 + _readI32(descriptorPrefix, 8);
  final name = _readCStringAtAddressFromBytes(bytes, allSections, nameAddress);
  return _isPlausibleSwiftTypeName(name) ? name : null;
}

String? _readRelativeSwiftStringFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength,
  List<MachOSection> allSections, {
  required int pointerAddress,
  required int relativeOffset,
}) {
  if (relativeOffset == 0) return null;
  final value = _readCStringAtAddressFromFile(
    raf,
    fileOffset,
    availableLength,
    allSections,
    pointerAddress + relativeOffset,
  );
  return _isPlausibleSwiftTypeName(value) ? value : null;
}

String? _readRelativeSwiftStringFromBytes(
  List<int> bytes,
  List<MachOSection> allSections, {
  required int pointerAddress,
  required int relativeOffset,
}) {
  if (relativeOffset == 0) return null;
  final value = _readCStringAtAddressFromBytes(
    bytes,
    allSections,
    pointerAddress + relativeOffset,
  );
  return _isPlausibleSwiftTypeName(value) ? value : null;
}

bool _isPlausibleSwiftTypeName(String? value) {
  if (value == null || value.isEmpty || value.length > 512) return false;
  return value.codeUnits.every((codeUnit) {
    return codeUnit >= 0x20 && codeUnit != 0x7f;
  });
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

Iterable<MachOSection> _objcCategoryListSections(
  List<MachOSegment> segments,
) sync* {
  for (final section in _allSections(segments)) {
    if (section.name == '__objc_catlist' ||
        section.name == '__objc_nlcatlist') {
      yield section;
    }
  }
}

Iterable<MachOSection> _objcProtocolReferenceSections(
  List<MachOSegment> segments,
) sync* {
  for (final section in _allSections(segments)) {
    if (section.name == '__objc_protolist' ||
        section.name == '__objc_protorefs') {
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
    '__swift5_reflstr',
    '__swift5_typeref',
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
  return _readPointerValue(bytes, 0, sections, is64Bit: is64Bit);
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

  return _readPointerValue(bytes, pointerOffset, sections, is64Bit: is64Bit);
}

int _readPointerValue(
  List<int> bytes,
  int offset,
  List<MachOSection> sections, {
  required bool is64Bit,
}) {
  final raw = is64Bit ? _readU64(bytes, offset) : _readU32(bytes, offset);
  return _normalizedPointerValue(raw, sections, is64Bit: is64Bit);
}

int _normalizedPointerValue(
  int raw,
  List<MachOSection> sections, {
  required bool is64Bit,
}) {
  if (!is64Bit ||
      raw == 0 ||
      _sectionContainingAddress(sections, raw) != null) {
    return raw;
  }

  final imageBase = _imageBaseAddress(sections);
  if (imageBase == null) return raw;

  final offsetTarget = raw & _dyldChainedPointer64TargetMask;
  final candidate = imageBase + offsetTarget;
  return _sectionContainingAddress(sections, candidate) == null
      ? raw
      : candidate;
}

int? _imageBaseAddress(List<MachOSection> sections) {
  int? minimumAddress;
  for (final section in sections) {
    if (section.address <= 0) continue;
    if (minimumAddress == null || section.address < minimumAddress) {
      minimumAddress = section.address;
    }
  }
  if (minimumAddress == null) return null;
  return minimumAddress - (minimumAddress % _machOPageSize);
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

int? _swiftFieldDescriptorByteLength(int fieldRecordSize, int fieldCount) {
  if (fieldRecordSize < _swiftFieldRecordMinimumBytes ||
      fieldRecordSize > _maxSwiftFieldRecordBytes ||
      fieldCount > _maxSwiftFieldCount) {
    return null;
  }

  final byteLength =
      _swiftFieldDescriptorHeaderBytes + fieldRecordSize * fieldCount;
  return byteLength <= _maxSwiftFieldDescriptorBytes ? byteLength : null;
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

bool _canReadRelativeObjCMethodListList(int entrySize, int entryCount) {
  if (entrySize < 8 || entryCount <= 0 || entryCount > _maxObjCMethodCount) {
    return false;
  }

  final byteLength = entrySize * entryCount;
  return byteLength > 0 && byteLength <= _maxObjCMethodListBytes;
}

bool _canReadObjCProtocolList(int pointerSize, int protocolCount) {
  if ((pointerSize != 4 && pointerSize != 8) ||
      protocolCount <= 0 ||
      protocolCount > _maxObjCProtocolCount) {
    return false;
  }

  final byteLength = pointerSize + pointerSize * protocolCount;
  return byteLength > 0 && byteLength <= _maxObjCProtocolListBytes;
}

bool _canReadObjCIvarList(int pointerSize, int entrySize, int entryCount) {
  if ((pointerSize != 4 && pointerSize != 8) ||
      entrySize < pointerSize * 3 + 8 ||
      entryCount <= 0 ||
      entryCount > _maxObjCIvarCount) {
    return false;
  }

  final byteLength = 8 + entrySize * entryCount;
  return byteLength > 0 && byteLength <= _maxObjCIvarListBytes;
}

bool _canReadObjCPropertyList(int pointerSize, int entrySize, int entryCount) {
  if ((pointerSize != 4 && pointerSize != 8) ||
      entrySize < pointerSize * 2 ||
      entryCount <= 0 ||
      entryCount > _maxObjCPropertyCount) {
    return false;
  }

  final byteLength = 8 + entrySize * entryCount;
  return byteLength > 0 && byteLength <= _maxObjCPropertyListBytes;
}

List<MachODyldBindSymbol> _readDyldBindSymbolsFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required List<MachODyldInfo> dyldInfos,
}) {
  final symbols = <MachODyldBindSymbol>[];
  for (final dyldInfo in dyldInfos) {
    symbols.addAll(
      _readDyldBindSymbolStreamFromFile(
        raf,
        fileOffset,
        availableLength,
        dyldInfo.bindOffset,
        dyldInfo.bindSize,
        source: 'LC_DYLD_INFO.bind',
      ),
    );
    symbols.addAll(
      _readDyldBindSymbolStreamFromFile(
        raf,
        fileOffset,
        availableLength,
        dyldInfo.weakBindOffset,
        dyldInfo.weakBindSize,
        source: 'LC_DYLD_INFO.weak_bind',
      ),
    );
    symbols.addAll(
      _readDyldBindSymbolStreamFromFile(
        raf,
        fileOffset,
        availableLength,
        dyldInfo.lazyBindOffset,
        dyldInfo.lazyBindSize,
        source: 'LC_DYLD_INFO.lazy_bind',
      ),
    );
  }
  return symbols;
}

List<MachODyldBindSymbol> _readDyldBindSymbolsFromBytes(
  List<int> bytes, {
  required List<MachODyldInfo> dyldInfos,
}) {
  final symbols = <MachODyldBindSymbol>[];
  for (final dyldInfo in dyldInfos) {
    symbols.addAll(
      _readDyldBindSymbolStreamFromBytes(
        bytes,
        dyldInfo.bindOffset,
        dyldInfo.bindSize,
        source: 'LC_DYLD_INFO.bind',
      ),
    );
    symbols.addAll(
      _readDyldBindSymbolStreamFromBytes(
        bytes,
        dyldInfo.weakBindOffset,
        dyldInfo.weakBindSize,
        source: 'LC_DYLD_INFO.weak_bind',
      ),
    );
    symbols.addAll(
      _readDyldBindSymbolStreamFromBytes(
        bytes,
        dyldInfo.lazyBindOffset,
        dyldInfo.lazyBindSize,
        source: 'LC_DYLD_INFO.lazy_bind',
      ),
    );
  }
  return symbols;
}

List<MachODyldBindSymbol> _readChainedFixupBindSymbolsFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required List<MachOChainedFixups> chainedFixups,
}) {
  final symbols = <MachODyldBindSymbol>[];
  for (final chainedFixup in chainedFixups) {
    if (!_canReadDyldInfoStream(
      chainedFixup.dataOffset,
      chainedFixup.dataSize,
      availableLength,
    )) {
      continue;
    }

    symbols.addAll(
      _parseChainedFixupBindSymbols(
        _readRange(
          raf,
          fileOffset + chainedFixup.dataOffset,
          chainedFixup.dataSize,
        ),
      ),
    );
  }
  return symbols;
}

List<MachODyldBindSymbol> _readChainedFixupBindSymbolsFromBytes(
  List<int> bytes, {
  required List<MachOChainedFixups> chainedFixups,
}) {
  final symbols = <MachODyldBindSymbol>[];
  for (final chainedFixup in chainedFixups) {
    if (!_canReadDyldInfoStream(
      chainedFixup.dataOffset,
      chainedFixup.dataSize,
      bytes.length,
    )) {
      continue;
    }

    symbols.addAll(
      _parseChainedFixupBindSymbols(
        bytes.sublist(
          chainedFixup.dataOffset,
          chainedFixup.dataOffset + chainedFixup.dataSize,
        ),
      ),
    );
  }
  return symbols;
}

List<MachODyldExportSymbol> _readDyldExportSymbolsFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength, {
  required List<MachODyldInfo> dyldInfos,
  required List<MachODyldExportsTrie> exportsTries,
}) {
  final symbols = <MachODyldExportSymbol>[];
  for (final dyldInfo in dyldInfos) {
    symbols.addAll(
      _readDyldExportTrieSymbolStreamFromFile(
        raf,
        fileOffset,
        availableLength,
        dyldInfo.exportOffset,
        dyldInfo.exportSize,
        source: 'LC_DYLD_INFO.export',
      ),
    );
  }

  for (final exportsTrie in exportsTries) {
    symbols.addAll(
      _readDyldExportTrieSymbolStreamFromFile(
        raf,
        fileOffset,
        availableLength,
        exportsTrie.dataOffset,
        exportsTrie.dataSize,
        source: 'LC_DYLD_EXPORTS_TRIE',
      ),
    );
  }
  return symbols;
}

List<MachODyldExportSymbol> _readDyldExportSymbolsFromBytes(
  List<int> bytes, {
  required List<MachODyldInfo> dyldInfos,
  required List<MachODyldExportsTrie> exportsTries,
}) {
  final symbols = <MachODyldExportSymbol>[];
  for (final dyldInfo in dyldInfos) {
    symbols.addAll(
      _readDyldExportTrieSymbolStreamFromBytes(
        bytes,
        dyldInfo.exportOffset,
        dyldInfo.exportSize,
        source: 'LC_DYLD_INFO.export',
      ),
    );
  }

  for (final exportsTrie in exportsTries) {
    symbols.addAll(
      _readDyldExportTrieSymbolStreamFromBytes(
        bytes,
        exportsTrie.dataOffset,
        exportsTrie.dataSize,
        source: 'LC_DYLD_EXPORTS_TRIE',
      ),
    );
  }
  return symbols;
}

List<MachODyldBindSymbol> _readDyldBindSymbolStreamFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength,
  int streamOffset,
  int streamSize, {
  required String source,
}) {
  if (!_canReadDyldInfoStream(streamOffset, streamSize, availableLength)) {
    return const [];
  }

  return _parseDyldBindSymbols(
    _readRange(raf, fileOffset + streamOffset, streamSize),
    source: source,
  );
}

List<MachODyldBindSymbol> _readDyldBindSymbolStreamFromBytes(
  List<int> bytes,
  int streamOffset,
  int streamSize, {
  required String source,
}) {
  if (!_canReadDyldInfoStream(streamOffset, streamSize, bytes.length)) {
    return const [];
  }

  return _parseDyldBindSymbols(
    bytes.sublist(streamOffset, streamOffset + streamSize),
    source: source,
  );
}

List<MachODyldExportSymbol> _readDyldExportTrieSymbolStreamFromFile(
  RandomAccessFile raf,
  int fileOffset,
  int availableLength,
  int streamOffset,
  int streamSize, {
  required String source,
}) {
  if (!_canReadDyldInfoStream(streamOffset, streamSize, availableLength)) {
    return const [];
  }

  return _parseDyldExportTrieSymbols(
    _readRange(raf, fileOffset + streamOffset, streamSize),
    source: source,
  );
}

List<MachODyldExportSymbol> _readDyldExportTrieSymbolStreamFromBytes(
  List<int> bytes,
  int streamOffset,
  int streamSize, {
  required String source,
}) {
  if (!_canReadDyldInfoStream(streamOffset, streamSize, bytes.length)) {
    return const [];
  }

  return _parseDyldExportTrieSymbols(
    bytes.sublist(streamOffset, streamOffset + streamSize),
    source: source,
  );
}

bool _canReadDyldInfoStream(
  int streamOffset,
  int streamSize,
  int availableLength,
) {
  return streamOffset > 0 &&
      streamSize > 0 &&
      streamSize <= _maxDyldInfoBytes &&
      _rangeWithin(streamOffset, streamSize, availableLength);
}

List<MachODyldBindSymbol> _parseDyldBindSymbols(
  List<int> bytes, {
  required String source,
}) {
  final symbols = <MachODyldBindSymbol>[];
  var offset = 0;
  while (offset < bytes.length) {
    final byte = bytes[offset];
    offset += 1;
    final opcode = byte & _bindOpcodeMask;

    if (opcode == _bindOpcodeSetSymbolTrailingFlagsImm) {
      final stringStart = offset;
      while (offset < bytes.length && bytes[offset] != 0) {
        offset += 1;
      }
      if (offset >= bytes.length) break;

      final name = latin1.decode(
        bytes.sublist(stringStart, offset),
        allowInvalid: true,
      );
      if (name.isNotEmpty) {
        symbols.add(MachODyldBindSymbol(name: name, source: source));
      }
      offset += 1;
      continue;
    }

    switch (opcode) {
      case _bindOpcodeSetDylibOrdinalUleb:
      case _bindOpcodeSetSegmentAndOffsetUleb:
      case _bindOpcodeAddAddrUleb:
      case _bindOpcodeDoBindAddAddrUleb:
        offset = _skipUleb128(bytes, offset);
      case _bindOpcodeSetAddendSleb:
        offset = _skipSleb128(bytes, offset);
      case _bindOpcodeDoBindUlebTimesSkippingUleb:
        offset = _skipUleb128(bytes, offset);
        offset = _skipUleb128(bytes, offset);
    }
  }
  return symbols;
}

List<MachODyldBindSymbol> _parseChainedFixupBindSymbols(List<int> bytes) {
  if (bytes.length < 28) return const [];

  final importsOffset = _readU32(bytes, 8);
  final symbolsOffset = _readU32(bytes, 12);
  final importsCount = _readU32(bytes, 16);
  final importsFormat = _readU32(bytes, 20);
  final symbolsFormat = _readU32(bytes, 24);
  if (importsCount <= 0 ||
      importsCount > _maxDyldImportCount ||
      !_rangeWithin(symbolsOffset, 1, bytes.length)) {
    return const [];
  }

  final symbolBytes = _chainedFixupSymbolBytes(
    bytes,
    offset: symbolsOffset,
    format: symbolsFormat,
  );
  if (symbolBytes == null || symbolBytes.isEmpty) return const [];

  final entrySize = switch (importsFormat) {
    _dyldChainedImport => 4,
    _dyldChainedImportAddend => 8,
    _dyldChainedImportAddend64 => 16,
    _ => 0,
  };
  final importsByteLength = importsCount * entrySize;
  if (entrySize <= 0 ||
      importsByteLength > _maxDyldInfoBytes ||
      !_rangeWithin(importsOffset, importsByteLength, bytes.length)) {
    return const [];
  }

  final symbols = <MachODyldBindSymbol>[];
  for (var i = 0; i < importsCount; i += 1) {
    final entryOffset = importsOffset + i * entrySize;
    final nameOffset = switch (importsFormat) {
      _dyldChainedImport => _readU32(bytes, entryOffset) >> 9,
      _dyldChainedImportAddend => _readU32(bytes, entryOffset) >> 9,
      _dyldChainedImportAddend64 =>
        (_readU64(bytes, entryOffset) >> 32) & 0xffffffff,
      _ => 0,
    };
    if (!_rangeWithin(nameOffset, 1, symbolBytes.length)) continue;

    final name = _readNullTerminatedString(
      symbolBytes,
      nameOffset,
      symbolBytes.length,
    );
    if (name.isEmpty) continue;

    symbols.add(
      MachODyldBindSymbol(name: name, source: 'LC_DYLD_CHAINED_FIXUPS.imports'),
    );
  }

  return symbols;
}

List<int>? _chainedFixupSymbolBytes(
  List<int> bytes, {
  required int offset,
  required int format,
}) {
  if (!_rangeWithin(offset, 1, bytes.length)) return null;

  final encoded = bytes.sublist(offset);
  return switch (format) {
    _dyldChainedSymbolsUncompressed => encoded,
    _dyldChainedSymbolsZlibCompressed => _zlibDecodeDyldInfo(encoded),
    _ => null,
  };
}

List<int>? _zlibDecodeDyldInfo(List<int> bytes) {
  try {
    final decoded = zlib.decode(bytes);
    if (decoded.length > _maxDyldInfoBytes) return null;
    return decoded;
  } on FormatException {
    return null;
  }
}

List<MachODyldExportSymbol> _parseDyldExportTrieSymbols(
  List<int> bytes, {
  required String source,
}) {
  final symbols = <MachODyldExportSymbol>[];
  final stack = <({int offset, String prefix})>[(offset: 0, prefix: '')];
  final visited = <int>{};

  while (stack.isNotEmpty && visited.length < _maxDyldExportTrieNodes) {
    final node = stack.removeLast();
    if (!_rangeWithin(node.offset, 1, bytes.length) ||
        !visited.add(node.offset)) {
      continue;
    }

    var cursor = node.offset;
    final terminalSizeResult = _readUleb128(bytes, cursor);
    if (terminalSizeResult == null) continue;
    final terminalSize = terminalSizeResult.value;
    cursor = terminalSizeResult.nextOffset;

    if (terminalSize > 0) {
      if (!_rangeWithin(cursor, terminalSize, bytes.length)) continue;
      if (node.prefix.isNotEmpty) {
        symbols.add(MachODyldExportSymbol(name: node.prefix, source: source));
      }
      cursor += terminalSize;
    }

    if (!_rangeWithin(cursor, 1, bytes.length)) continue;
    final childCount = bytes[cursor];
    cursor += 1;

    for (var i = 0; i < childCount; i += 1) {
      final edgeStart = cursor;
      while (cursor < bytes.length && bytes[cursor] != 0) {
        cursor += 1;
      }
      if (cursor >= bytes.length) break;

      final edge = latin1.decode(
        bytes.sublist(edgeStart, cursor),
        allowInvalid: true,
      );
      cursor += 1;

      final childOffsetResult = _readUleb128(bytes, cursor);
      if (childOffsetResult == null) break;
      cursor = childOffsetResult.nextOffset;

      final childOffset = childOffsetResult.value;
      if (childOffset <= 0 || childOffset >= bytes.length) continue;
      stack.add((offset: childOffset, prefix: '${node.prefix}$edge'));
    }
  }

  return symbols;
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

int _signExtend(int value, int width) {
  final signBit = 1 << (width - 1);
  final mask = (1 << width) - 1;
  final truncated = value & mask;
  return (truncated & signBit) == 0 ? truncated : truncated - (1 << width);
}

_Uleb128Result? _readUleb128(List<int> bytes, int offset) {
  var result = 0;
  var shift = 0;
  var cursor = offset;
  while (cursor < bytes.length && shift < 64) {
    final byte = bytes[cursor];
    cursor += 1;
    result |= (byte & 0x7f) << shift;
    if ((byte & 0x80) == 0) {
      return _Uleb128Result(value: result, nextOffset: cursor);
    }
    shift += 7;
  }
  return null;
}

int _skipUleb128(List<int> bytes, int offset) {
  while (offset < bytes.length) {
    final byte = bytes[offset];
    offset += 1;
    if ((byte & 0x80) == 0) break;
  }
  return offset;
}

int _skipSleb128(List<int> bytes, int offset) {
  return _skipUleb128(bytes, offset);
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
const _bindOpcodeMask = 0xf0;
const _bindOpcodeSetDylibOrdinalUleb = 0x20;
const _bindOpcodeSetSymbolTrailingFlagsImm = 0x40;
const _bindOpcodeSetAddendSleb = 0x60;
const _bindOpcodeSetSegmentAndOffsetUleb = 0x70;
const _bindOpcodeAddAddrUleb = 0x80;
const _bindOpcodeDoBindAddAddrUleb = 0xa0;
const _bindOpcodeDoBindUlebTimesSkippingUleb = 0xc0;
const _dyldChainedImport = 1;
const _dyldChainedImportAddend = 2;
const _dyldChainedImportAddend64 = 3;
const _dyldChainedSymbolsUncompressed = 0;
const _dyldChainedSymbolsZlibCompressed = 1;
const _maxDyldExportTrieNodes = 8192;
const _maxDyldImportCount = 1 << 20;
const _maxFatArchTableBytes = 64 * 1024;
const _maxDyldInfoBytes = 16 * 1024 * 1024;
const _maxLoadCommandBytes = 8 * 1024 * 1024;
const _objcDirectSelectorMethodListFlag = 0x40000000;
const _objcRelativeMethodListsFlag = 0x1;
const _objcSmallMethodListFlag = 0x80000000;
const _swiftFieldDescriptorHeaderBytes = 16;
const _swiftFieldRecordMinimumBytes = 12;
const _dyldChainedPointer64TargetMask = 0x0000000fffffffff;
const _machOPageSize = 0x4000;
const _maxSwiftFieldCount = 8192;
const _maxSwiftFieldDescriptorBytes = 2 * 1024 * 1024;
const _maxSwiftFieldRecordBytes = 4096;
const _maxObjCMethodCount = 8192;
const _maxObjCMethodListBytes = 2 * 1024 * 1024;
const _maxObjCProtocolCount = 8192;
const _maxObjCProtocolListBytes = 2 * 1024 * 1024;
const _maxObjCIvarCount = 8192;
const _maxObjCIvarListBytes = 2 * 1024 * 1024;
const _maxObjCPropertyCount = 8192;
const _maxObjCPropertyListBytes = 2 * 1024 * 1024;
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
const _lcEncryptionInfo = 0x21;
const _lcDyldInfo = 0x22;
const _lcDyldInfoOnly = 0x80000022;
const _lcLoadUpwardDylib = 0x80000023;
const _lcSourceVersion = 0x2a;
const _lcEncryptionInfo64 = 0x2c;
const _lcBuildVersion = 0x32;
const _lcDyldExportsTrie = 0x80000033;
const _lcDyldChainedFixups = 0x80000034;
const _lcVersionMinMacosx = 0x24;
const _lcVersionMinIphoneos = 0x25;
const _lcVersionMinTvos = 0x2f;
const _lcVersionMinWatchos = 0x30;
