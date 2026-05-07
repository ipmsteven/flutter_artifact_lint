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
  const MachOSection({required this.segmentName, required this.name});

  final String segmentName;
  final String name;

  String get displayName => '$segmentName.$name';
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
    final headerSize = switch (magic) {
      _mhMagic64 => 32,
      _mhMagic => 28,
      _ => null,
    };
    if (headerSize == null || headerPrefix.length < headerSize) {
      return const MachOReport(linkedDylibs: []);
    }

    final sizeofcmds = _readU32(headerPrefix, 20);
    final commandBytes = sizeofcmds > _maxLoadCommandBytes
        ? _maxLoadCommandBytes
        : sizeofcmds;
    final thinBytes = _readRange(
      raf,
      fileOffset,
      _boundedEnd(headerSize, commandBytes, availableLength),
    );
    return _parseThin(thinBytes);
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
  );
}

class _MachOHeader {
  const _MachOHeader({
    required this.cpuType,
    required this.cpuSubtype,
    required this.commandCount,
    required this.loadCommandsOffset,
    required this.loadCommandsEnd,
  });

  final int cpuType;
  final int cpuSubtype;
  final int commandCount;
  final int loadCommandsOffset;
  final int loadCommandsEnd;
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
      ),
    );
  }

  return MachOSegment(name: segmentName, sections: sections);
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

int _readU32(List<int> bytes, int offset) {
  if (offset + 4 > bytes.length) return 0;
  return bytes[offset] |
      (bytes[offset + 1] << 8) |
      (bytes[offset + 2] << 16) |
      (bytes[offset + 3] << 24);
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
const _mhMagic = 0xfeedface;
const _mhMagic64 = 0xfeedfacf;
const _lcSegment = 0x01;
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
