import 'dart:convert';

class MachOReport {
  const MachOReport({
    required this.linkedDylibs,
    this.architectures = const [],
    this.buildVersions = const [],
  });

  final List<MachODylib> linkedDylibs;
  final List<MachOArchitecture> architectures;
  final List<MachOBuildVersion> buildVersions;
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

  String get name => switch (cpuType) {
    0x0100000c => 'arm64',
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

class MachOParser {
  const MachOParser();

  MachOReport parse(List<int> bytes) {
    final fatReport = _parseFat(bytes);
    if (fatReport != null) return fatReport;

    final thinReport = _parseThin(bytes);
    return _deduplicatedReport(
      thinReport.linkedDylibs,
      thinReport.architectures,
      thinReport.buildVersions,
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
      }

      offset += archSize;
    }

    return _deduplicatedReport(linkedDylibs, architectures, buildVersions);
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
    var offset = header.loadCommandsOffset;

    for (var i = 0; i < header.commandCount; i += 1) {
      if (offset + 8 > header.loadCommandsEnd) break;

      final command = _readU32(bytes, offset);
      final commandSize = _readU32(bytes, offset + 4);
      if (commandSize < 8 || offset + commandSize > header.loadCommandsEnd) {
        break;
      }

      if (_isDylibLoadCommand(command) && commandSize >= 24) {
        final nameOffset = _readU32(bytes, offset + 8);
        final nameStart = offset + nameOffset;
        if (nameOffset >= 24 && nameStart < offset + commandSize) {
          final path = _readNullTerminatedString(
            bytes,
            nameStart,
            offset + commandSize,
          );
          if (path.isNotEmpty) {
            linkedDylibs.add(
              MachODylib(path: path, weak: command == _lcLoadWeakDylib),
            );
          }
        }
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

      offset += commandSize;
    }

    return MachOReport(
      linkedDylibs: linkedDylibs,
      architectures: architectures,
      buildVersions: buildVersions,
    );
  }
}

MachOReport _deduplicatedReport(
  List<MachODylib> dylibs, [
  List<MachOArchitecture> architectures = const [],
  List<MachOBuildVersion> buildVersions = const [],
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

  return MachOReport(
    linkedDylibs: byPath.values.toList(),
    architectures: byArchitecture.values.toList(),
    buildVersions: byBuildVersion.values.toList(),
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

bool _isDylibLoadCommand(int command) {
  return {
    _lcLoadDylib,
    _lcLoadWeakDylib,
    _lcReexportDylib,
    _lcLazyLoadDylib,
    _lcLoadUpwardDylib,
  }.contains(command);
}

String _readNullTerminatedString(List<int> bytes, int start, int end) {
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

const _fatMagic = 0xcafebabe;
const _fatMagic64 = 0xcafebabf;
const _mhMagic = 0xfeedface;
const _mhMagic64 = 0xfeedfacf;
const _lcLoadDylib = 0x0c;
const _lcLoadWeakDylib = 0x80000018;
const _lcReexportDylib = 0x8000001f;
const _lcLazyLoadDylib = 0x20;
const _lcLoadUpwardDylib = 0x80000023;
const _lcBuildVersion = 0x32;
