import 'dart:convert';

class MachOReport {
  const MachOReport({required this.linkedDylibs});

  final List<MachODylib> linkedDylibs;
}

class MachODylib {
  const MachODylib({required this.path, required this.weak});

  final String path;
  final bool weak;
}

class MachOParser {
  const MachOParser();

  MachOReport parse(List<int> bytes) {
    final header = _readHeader(bytes);
    if (header == null) {
      return const MachOReport(linkedDylibs: []);
    }

    final linkedDylibs = <MachODylib>[];
    var offset = header.loadCommandsOffset;

    for (var i = 0; i < header.commandCount; i += 1) {
      if (offset + 8 > bytes.length) break;

      final command = _readU32(bytes, offset);
      final commandSize = _readU32(bytes, offset + 4);
      if (commandSize < 8 || offset + commandSize > bytes.length) break;

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

      offset += commandSize;
    }

    return MachOReport(linkedDylibs: linkedDylibs);
  }
}

class _MachOHeader {
  const _MachOHeader({
    required this.commandCount,
    required this.loadCommandsOffset,
  });

  final int commandCount;
  final int loadCommandsOffset;
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
    commandCount: _readU32(bytes, 16),
    loadCommandsOffset: headerSize,
  );
}

bool _isDylibLoadCommand(int command) {
  return command == _lcLoadDylib || command == _lcLoadWeakDylib;
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

const _mhMagic = 0xfeedface;
const _mhMagic64 = 0xfeedfacf;
const _lcLoadDylib = 0x0c;
const _lcLoadWeakDylib = 0x80000018;
