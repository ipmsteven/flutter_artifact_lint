import 'dart:convert';
import 'dart:io';

import 'package:flutter_artifact_lint/src/ios_artifact_scanner.dart';
import 'package:flutter_artifact_lint/src/model.dart';
import 'package:test/test.dart';

void main() {
  group('Mach-O load command parser acceptance', () {
    for (final gap in _systemFrameworkLoadCommandGaps) {
      test(
        'reports ${gap.expectedRuleId} when ${gap.frameworkName}.framework only appears in a Mach-O load command',
        () async {
          final result = await _scanAppWithMainBinary(
            _machOLoadDylibBytes(
              '/System/Library/Frameworks/${gap.frameworkName}.framework/${gap.frameworkName}',
            ),
          );

          expect(_ruleIds(result.warned), contains(gap.expectedRuleId));
        },
      );
    }

    test(
      'reports private framework links that are visible only as Mach-O load commands',
      () async {
        final result = await _scanAppWithMainBinary(
          _machOLoadDylibBytes(
            '/System/Library/PrivateFrameworks/Preferences.framework/Preferences',
          ),
        );

        final finding = result.warned.singleWhere(
          (finding) => finding.ruleId == 'ios.private_api.framework',
        );

        expect(finding.evidence, anyElement(contains('Preferences.framework')));
      },
    );

    test(
      'reports weak-linked permission frameworks from Mach-O load commands',
      () async {
        final result = await _scanAppWithMainBinary(
          _machOLoadDylibBytes(
            '/System/Library/Frameworks/Contacts.framework/Contacts',
            weak: true,
          ),
        );

        expect(
          _ruleIds(result.warned),
          contains('ios.permission.contacts.missing'),
        );
      },
    );

    test('reports permission evidence from a fat Mach-O main binary', () async {
      final result = await _scanAppWithMainBinary(
        _fatMachO([
          _machOLoadDylibBytes(
            '/System/Library/Frameworks/Photos.framework/Photos',
          ),
        ]),
      );

      expect(
        _ruleIds(result.warned),
        contains('ios.permission.photos.missing'),
      );
    });
  });

  group('Mach-O build metadata parser acceptance', () {
    test(
      'reports deployment target metadata stored as LC_BUILD_VERSION fields',
      () async {
        final result = await _scanAppWithMainBinary(_machOBuildVersionBytes());
        final finding = result.info.singleWhere(
          (finding) => finding.ruleId == 'ios.macho.build_version',
        );

        expect(finding.message, contains('iOS'));
        expect(finding.message, contains('minimum OS 12.0.0'));
        expect(finding.message, contains('SDK 17.0.0'));
      },
    );

    test('reports LC_BUILD_VERSION tool metadata', () async {
      final result = await _scanAppWithMainBinary(
        _machOBuildVersionBytes(tools: [(tool: 1, version: 0x000f0000)]),
      );
      final finding = result.info.singleWhere(
        (finding) => finding.ruleId == 'ios.macho.build_version',
      );

      expect(finding.message, contains('clang 15.0.0'));
      expect(finding.evidence, contains('clang'));
      expect(finding.evidence, contains('15.0.0'));
    });
  });

  group('Mach-O diagnostic metadata parser acceptance', () {
    test(
      'reports rpath dylib id uuid source version and code signature',
      () async {
        final result = await _scanAppWithMainBinary(
          _machOBytes([
            _machOPathCommand(0x8000001c, '@executable_path/Frameworks'),
            _machODylibIdCommand('@rpath/Runner.framework/Runner'),
            _machOUuidCommand([
              0x00,
              0x11,
              0x22,
              0x33,
              0x44,
              0x55,
              0x66,
              0x77,
              0x88,
              0x99,
              0xaa,
              0xbb,
              0xcc,
              0xdd,
              0xee,
              0xff,
            ]),
            _machOSourceVersionCommand(_sourceVersion(1, 2, 3, 4, 5)),
            _machOCodeSignatureCommand(dataOffset: 4096, dataSize: 512),
          ]),
        );

        expect(_ruleIds(result.info), contains('ios.macho.rpath'));
        expect(_ruleIds(result.info), contains('ios.macho.dylib_id'));
        expect(_ruleIds(result.info), contains('ios.macho.uuid'));
        expect(_ruleIds(result.info), contains('ios.macho.source_version'));
        expect(_ruleIds(result.info), contains('ios.macho.code_signature'));
      },
    );

    test('reports FairPlay encryption info load command metadata', () async {
      final result = await _scanAppWithMainBinary(
        _machOBytes([
          _machOEncryptionInfoCommand(
            cryptOffset: 8192,
            cryptSize: 4096,
            cryptId: 1,
          ),
        ]),
      );

      final finding = result.info.singleWhere(
        (finding) => finding.ruleId == 'ios.macho.encryption_info',
      );

      expect(finding.message, contains('offset 8192'));
      expect(finding.message, contains('size 4096'));
      expect(finding.message, contains('crypt id 1'));
    });

    test('reports entry point load command metadata', () async {
      final result = await _scanAppWithMainBinary(
        _machOBytes([
          _machOMainCommand(entryOffset: 0x1234, stackSize: 0x4000),
        ]),
      );

      final finding = result.info.singleWhere(
        (finding) => finding.ruleId == 'ios.macho.entry_point',
      );

      expect(finding.message, contains('entry offset 4660'));
      expect(finding.message, contains('stack size 16384'));
    });

    test('reports chained fixups starts metadata', () async {
      final result = await _scanAppWithMainBinary(_machOWithChainedFixups());

      final finding = result.info.singleWhere(
        (finding) => finding.ruleId == 'ios.macho.chained_fixups',
      );

      expect(finding.message, contains('imports 0'));
      expect(finding.message, contains('pointer format 9'));
      expect(finding.message, contains('page size 16384'));
    });

    test('reports function starts metadata', () async {
      final result = await _scanAppWithMainBinary(
        _machOWithFunctionStarts([0x100, 0x120, 0x1a0]),
      );

      final finding = result.info.singleWhere(
        (finding) => finding.ruleId == 'ios.macho.function_starts',
      );

      expect(finding.message, contains('count 3'));
      expect(finding.message, contains('first offset 256'));
      expect(finding.message, contains('last offset 416'));
    });

    test('reports data-in-code metadata', () async {
      final result = await _scanAppWithMainBinary(
        _machOWithDataInCode([
          (offset: 0x20, length: 8, kind: 1),
          (offset: 0x80, length: 16, kind: 4),
        ]),
      );

      final finding = result.info.singleWhere(
        (finding) => finding.ruleId == 'ios.macho.data_in_code',
      );

      expect(finding.message, contains('entries 2'));
      expect(finding.message, contains('data'));
      expect(finding.message, contains('jump table 32'));
    });

    test('reports linker option metadata', () async {
      final result = await _scanAppWithMainBinary(
        _machOBytes([
          _machOLinkerOptionCommand(['-framework', 'Contacts']),
        ]),
      );

      final finding = result.info.singleWhere(
        (finding) => finding.ruleId == 'ios.macho.linker_option',
      );

      expect(finding.message, contains('-framework'));
      expect(finding.message, contains('Contacts'));
    });

    test('reports dyld string load command metadata', () async {
      final result = await _scanAppWithMainBinary(
        _machOBytes([
          _machOPathCommand(0x0e, '/usr/lib/dyld'),
          _machOPathCommand(
            0x27,
            'DYLD_INSERT_LIBRARIES=@executable_path/Inject.dylib',
          ),
        ]),
      );

      final dylinkerFinding = result.info.singleWhere(
        (finding) => finding.ruleId == 'ios.macho.dylinker',
      );
      final environmentFinding = result.info.singleWhere(
        (finding) => finding.ruleId == 'ios.macho.dyld_environment',
      );

      expect(dylinkerFinding.message, contains('/usr/lib/dyld'));
      expect(environmentFinding.message, contains('DYLD_INSERT_LIBRARIES'));
    });

    test('reports LC_NOTE metadata', () async {
      final result = await _scanAppWithMainBinary(
        _machOBytes([
          _machONoteCommand(owner: 'Swift', offset: 4096, size: 64),
        ]),
      );

      final finding = result.info.singleWhere(
        (finding) => finding.ruleId == 'ios.macho.note',
      );

      expect(finding.message, contains('Swift'));
      expect(finding.message, contains('offset 4096'));
      expect(finding.message, contains('size 64'));
    });

    test('reports LC_TARGET_TRIPLE metadata', () async {
      final result = await _scanAppWithMainBinary(
        _machOBytes([_machOPathCommand(0x39, 'arm64e-apple-ios17.0')]),
      );

      final finding = result.info.singleWhere(
        (finding) => finding.ruleId == 'ios.macho.target_triple',
      );

      expect(finding.message, contains('arm64e-apple-ios17.0'));
    });

    test('reports generic linkedit data metadata', () async {
      final result = await _scanAppWithMainBinary(
        _machOBytes([
          _machOLinkeditDataCommand(
            command: 0x2e,
            dataOffset: 4096,
            dataSize: 128,
          ),
        ]),
      );

      final finding = result.info.singleWhere(
        (finding) => finding.ruleId == 'ios.macho.linkedit_data',
      );

      expect(finding.message, contains('LC_LINKER_OPTIMIZATION_HINT'));
      expect(finding.message, contains('offset 4096'));
      expect(finding.message, contains('size 128'));
    });
  });

  group('Mach-O architecture parser acceptance', () {
    test('reports Mach-O header file type and flags', () async {
      final result = await _scanAppWithMainBinary(
        _machOHeaderBytes(flags: 0x00200000 | 0x01000000),
      );

      final finding = result.info.singleWhere(
        (finding) => finding.ruleId == 'ios.macho.header',
      );

      expect(finding.message, contains('MH_EXECUTE'));
      expect(finding.message, contains('MH_PIE'));
      expect(finding.message, contains('MH_NO_HEAP_EXECUTION'));
    });

    test(
      'reports architecture inventory from a fat Mach-O main binary',
      () async {
        final result = await _scanAppWithMainBinary(
          _fatMachO([
            _machOHeaderBytes(),
            _machOHeaderBytes(cpuType: 0x01000007),
          ]),
        );
        final finding = result.info.singleWhere(
          (finding) => finding.ruleId == 'ios.macho.architecture',
        );

        expect(finding.message, contains('arm64'));
        expect(finding.message, contains('x86_64'));
      },
    );

    test('warns when a simulator architecture slice is present', () async {
      final result = await _scanAppWithMainBinary(
        _fatMachO([
          _machOHeaderBytes(),
          _machOHeaderBytes(cpuType: 0x01000007),
        ]),
      );

      expect(_ruleIds(result.warned), contains('ios.macho.simulator_slice'));
    });

    test('warns when simulator platform metadata is present', () async {
      final result = await _scanAppWithMainBinary(
        _machOBuildVersionBytes(platform: 7),
      );

      expect(_ruleIds(result.warned), contains('ios.macho.simulator_slice'));
    });
  });

  group('known String Scanner gaps', () {
    test(
      'misses push capability when evidence only exists in signed-artifact entitlements',
      () async {
        final fixture = await GapFixture.create();
        addTearDown(fixture.delete);

        fixture.writeInfoPlist(_validBasePlist());
        fixture.writeMainBinary(_machOHeaderBytes());
        fixture.writeFile(
          'archived-expanded-entitlements.xcent',
          _plist({'aps-environment': 'production'}),
        );
        fixture.writeFile('_CodeSignature/CodeResources', 'signed');

        final result = await IosArtifactScanner().scan(fixture.appPath);

        expect(result.artifact.type, ArtifactType.signedApp);
        expect(
          _ruleIds(result.warned),
          isNot(contains('ios.notification.evidence')),
        );
      },
    );
  });
}

const _systemFrameworkLoadCommandGaps = [
  (
    frameworkName: 'Contacts',
    expectedRuleId: 'ios.permission.contacts.missing',
  ),
  (
    frameworkName: 'CoreLocation',
    expectedRuleId: 'ios.permission.location.missing',
  ),
  (frameworkName: 'Photos', expectedRuleId: 'ios.permission.photos.missing'),
  (
    frameworkName: 'CoreBluetooth',
    expectedRuleId: 'ios.permission.bluetooth.missing',
  ),
  (
    frameworkName: 'LocalAuthentication',
    expectedRuleId: 'ios.permission.face_id.missing',
  ),
  (
    frameworkName: 'UserNotifications',
    expectedRuleId: 'ios.notification.evidence',
  ),
];

Future<ScanResult> _scanAppWithMainBinary(List<int> bytes) async {
  final fixture = await GapFixture.create();
  addTearDown(fixture.delete);

  fixture.writeInfoPlist(_validBasePlist());
  fixture.writeMainBinary(bytes);

  return IosArtifactScanner().scan(fixture.appPath);
}

List<String> _ruleIds(List<LintFinding> findings) {
  return findings.map((finding) => finding.ruleId).toList();
}

List<int> _machOLoadDylibBytes(String dylibPath, {bool weak = false}) {
  final pathBytes = [...latin1.encode(dylibPath), 0];
  final commandSize = 24 + pathBytes.length;
  return [
    ..._machOHeaderBytes(sizeofcmds: commandSize),
    ..._u32(weak ? 0x80000018 : 0x0c),
    ..._u32(commandSize),
    ..._u32(24), // dylib.name offset
    ..._u32(0), // timestamp
    ..._u32(0x00010000), // current version 1.0.0
    ..._u32(0x00010000), // compatibility version 1.0.0
    ...pathBytes,
  ];
}

List<int> _machOBytes(List<List<int>> commands) {
  return [
    ..._machOHeaderBytes(
      ncmds: commands.length,
      sizeofcmds: commands.fold(0, (total, command) => total + command.length),
    ),
    for (final command in commands) ...command,
  ];
}

List<int> _fatMachO(List<List<int>> slices) {
  const headerSize = 8;
  const archSize = 20;
  var nextOffset = headerSize + archSize * slices.length;
  final archHeaders = <int>[];
  final payload = <int>[];

  for (final slice in slices) {
    archHeaders
      ..addAll(_u32be(0x0100000c)) // CPU_TYPE_ARM64
      ..addAll(_u32be(0)) // CPU_SUBTYPE_ARM64_ALL
      ..addAll(_u32be(nextOffset))
      ..addAll(_u32be(slice.length))
      ..addAll(_u32be(0)); // align
    payload.addAll(slice);
    nextOffset += slice.length;
  }

  return [
    ..._u32be(0xcafebabe),
    ..._u32be(slices.length),
    ...archHeaders,
    ...payload,
  ];
}

List<int> _machOBuildVersionBytes({
  int platform = 2,
  List<({int tool, int version})> tools = const [],
}) {
  final commandSize = 24 + tools.length * 8;
  return [
    ..._machOHeaderBytes(sizeofcmds: commandSize),
    0x32, 0x00, 0x00, 0x00, // LC_BUILD_VERSION
    ..._u32(commandSize),
    ..._u32(platform),
    0x00, 0x00, 0x0c, 0x00, // minos 12.0.0
    0x00, 0x00, 0x11, 0x00, // sdk 17.0.0
    ..._u32(tools.length),
    for (final tool in tools) ...[..._u32(tool.tool), ..._u32(tool.version)],
  ];
}

List<int> _machOHeaderBytes({
  int ncmds = 0,
  int sizeofcmds = 0,
  int cpuType = 0x0100000c,
  int fileType = 2,
  int flags = 0,
}) {
  return [
    0xcf, 0xfa, 0xed, 0xfe, // MH_MAGIC_64
    ..._u32(cpuType),
    ..._u32(0), // CPU_SUBTYPE_ARM64_ALL
    ..._u32(fileType),
    ..._u32(ncmds == 0 && sizeofcmds != 0 ? 1 : ncmds),
    ..._u32(sizeofcmds),
    ..._u32(flags),
    ..._u32(0), // reserved
  ];
}

List<int> _machOPathCommand(int command, String path) {
  final pathBytes = [...latin1.encode(path), 0];
  final commandSize = 12 + pathBytes.length;
  return [..._u32(command), ..._u32(commandSize), ..._u32(12), ...pathBytes];
}

List<int> _machODylibIdCommand(String dylibPath) {
  final pathBytes = [...latin1.encode(dylibPath), 0];
  final commandSize = 24 + pathBytes.length;
  return [
    ..._u32(0x0d),
    ..._u32(commandSize),
    ..._u32(24),
    ..._u32(0),
    ..._u32(0x00010000),
    ..._u32(0x00010000),
    ...pathBytes,
  ];
}

List<int> _machOUuidCommand(List<int> uuid) {
  return [..._u32(0x1b), ..._u32(24), ...uuid];
}

List<int> _machOSourceVersionCommand(int version) {
  return [..._u32(0x2a), ..._u32(16), ..._u64(version)];
}

List<int> _machOCodeSignatureCommand({
  required int dataOffset,
  required int dataSize,
}) {
  return [..._u32(0x1d), ..._u32(16), ..._u32(dataOffset), ..._u32(dataSize)];
}

List<int> _machOLinkerOptionCommand(List<String> values) {
  final strings = [
    for (final value in values) ...[...latin1.encode(value), 0],
  ];
  final commandSize = _alignTo(12 + strings.length, 8);
  return [
    ..._u32(0x2d),
    ..._u32(commandSize),
    ..._u32(values.length),
    ...strings,
    ...List.filled(commandSize - 12 - strings.length, 0),
  ];
}

List<int> _machONoteCommand({
  required String owner,
  required int offset,
  required int size,
}) {
  final ownerBytes = latin1.encode(owner).take(16).toList();
  return [
    ..._u32(0x31),
    ..._u32(40),
    ...ownerBytes,
    ...List.filled(16 - ownerBytes.length, 0),
    ..._u64(offset),
    ..._u64(size),
  ];
}

List<int> _machOLinkeditDataCommand({
  required int command,
  required int dataOffset,
  required int dataSize,
}) {
  return [
    ..._u32(command),
    ..._u32(16),
    ..._u32(dataOffset),
    ..._u32(dataSize),
  ];
}

List<int> _machOEncryptionInfoCommand({
  required int cryptOffset,
  required int cryptSize,
  required int cryptId,
}) {
  return [
    ..._u32(0x21),
    ..._u32(20),
    ..._u32(cryptOffset),
    ..._u32(cryptSize),
    ..._u32(cryptId),
  ];
}

List<int> _machOMainCommand({
  required int entryOffset,
  required int stackSize,
}) {
  return [
    ..._u32(0x80000028),
    ..._u32(24),
    ..._u64(entryOffset),
    ..._u64(stackSize),
  ];
}

List<int> _machOWithChainedFixups() {
  final chainedFixups = _chainedFixupsPayload();
  final dataOffset = 32 + 16;
  return [
    ..._machOHeaderBytes(ncmds: 1, sizeofcmds: 16),
    ..._u32(0x80000034),
    ..._u32(16),
    ..._u32(dataOffset),
    ..._u32(chainedFixups.length),
    ...chainedFixups,
  ];
}

List<int> _machOWithFunctionStarts(List<int> offsets) {
  final functionStarts = _functionStartsBytes(offsets);
  final dataOffset = 32 + 16;
  return [
    ..._machOHeaderBytes(ncmds: 1, sizeofcmds: 16),
    ..._u32(0x26),
    ..._u32(16),
    ..._u32(dataOffset),
    ..._u32(functionStarts.length),
    ...functionStarts,
  ];
}

List<int> _machOWithDataInCode(
  List<({int offset, int length, int kind})> entries,
) {
  final dataInCode = _dataInCodeBytes(entries);
  final dataOffset = 32 + 16;
  return [
    ..._machOHeaderBytes(ncmds: 1, sizeofcmds: 16),
    ..._u32(0x29),
    ..._u32(16),
    ..._u32(dataOffset),
    ..._u32(dataInCode.length),
    ...dataInCode,
  ];
}

List<int> _dataInCodeBytes(List<({int offset, int length, int kind})> entries) {
  return [
    for (final entry in entries) ...[
      ..._u32(entry.offset),
      ..._u16(entry.length),
      ..._u16(entry.kind),
    ],
  ];
}

List<int> _functionStartsBytes(List<int> offsets) {
  final result = <int>[];
  var previous = 0;
  for (final offset in offsets) {
    result.addAll(_uleb128(offset - previous));
    previous = offset;
  }
  result.add(0);
  return result;
}

List<int> _chainedFixupsPayload() {
  final starts = _chainedStartsInImagePayload();
  const headerSize = 28;
  final importsOffset = headerSize + starts.length;
  return [
    ..._u32(0),
    ..._u32(headerSize),
    ..._u32(importsOffset),
    ..._u32(importsOffset),
    ..._u32(0),
    ..._u32(1),
    ..._u32(0),
    ...starts,
  ];
}

List<int> _chainedStartsInImagePayload() {
  const pageStarts = [0x18, 0xffff];
  final segmentStarts = [
    ..._u32(22 + pageStarts.length * 2),
    ..._u16(0x4000),
    ..._u16(9),
    ..._u64(0x8000),
    ..._u32(0),
    ..._u16(pageStarts.length),
    for (final pageStart in pageStarts) ..._u16(pageStart),
  ];
  return [..._u32(1), ..._u32(8), ...segmentStarts];
}

int _sourceVersion(int a, int b, int c, int d, int e) {
  return (a << 40) | (b << 30) | (c << 20) | (d << 10) | e;
}

int _alignTo(int value, int alignment) {
  final remainder = value % alignment;
  return remainder == 0 ? value : value + alignment - remainder;
}

List<int> _u32(int value) {
  return [
    value & 0xff,
    (value >> 8) & 0xff,
    (value >> 16) & 0xff,
    (value >> 24) & 0xff,
  ];
}

List<int> _u32be(int value) {
  return [
    (value >> 24) & 0xff,
    (value >> 16) & 0xff,
    (value >> 8) & 0xff,
    value & 0xff,
  ];
}

List<int> _u16(int value) {
  return [value & 0xff, (value >> 8) & 0xff];
}

List<int> _uleb128(int value) {
  final result = <int>[];
  var remaining = value;
  do {
    var byte = remaining & 0x7f;
    remaining >>= 7;
    if (remaining != 0) byte |= 0x80;
    result.add(byte);
  } while (remaining != 0);
  return result;
}

List<int> _u64(int value) {
  return [
    value & 0xff,
    (value >> 8) & 0xff,
    (value >> 16) & 0xff,
    (value >> 24) & 0xff,
    (value >> 32) & 0xff,
    (value >> 40) & 0xff,
    (value >> 48) & 0xff,
    (value >> 56) & 0xff,
  ];
}

Map<String, Object?> _validBasePlist() => {
  'CFBundleIdentifier': 'com.example.runner',
  'CFBundleShortVersionString': '1.2.3',
  'CFBundleVersion': '45',
  'UILaunchStoryboardName': 'LaunchScreen',
  'UISupportedInterfaceOrientations': ['UIInterfaceOrientationPortrait'],
  'ITSAppUsesNonExemptEncryption': false,
};

class GapFixture {
  GapFixture._(this._root, this.appPath);

  final Directory _root;
  final String appPath;

  static Future<GapFixture> create() async {
    final root = await Directory.systemTemp.createTemp('fal_gap_matrix_');
    final app = Directory('${root.path}/Runner.app')..createSync();
    return GapFixture._(root, app.path);
  }

  void delete() => _root.deleteSync(recursive: true);

  void writeInfoPlist(Map<String, Object?> values) {
    writeFile('Info.plist', _plist(values));
  }

  void writeMainBinary(List<int> bytes) {
    final file = File('$appPath/Runner')..createSync(recursive: true);
    file.writeAsBytesSync(bytes);
  }

  void writeFile(String relativePath, String content) {
    final file = File('$appPath/$relativePath')..createSync(recursive: true);
    file.writeAsStringSync(content);
  }
}

String _plist(Map<String, Object?> values) {
  final buffer = StringBuffer()
    ..writeln('<?xml version="1.0" encoding="UTF-8"?>')
    ..writeln(
      '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
      '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
    )
    ..writeln('<plist version="1.0">')
    ..writeln(_dict(values))
    ..writeln('</plist>');
  return buffer.toString();
}

String _dict(Map<String, Object?> values) {
  final buffer = StringBuffer()..writeln('<dict>');
  for (final entry in values.entries) {
    buffer.writeln('<key>${entry.key}</key>');
    buffer.write(_value(entry.value));
  }
  buffer.writeln('</dict>');
  return buffer.toString();
}

String _value(Object? value) {
  if (value is bool) return value ? '<true/>\n' : '<false/>\n';
  if (value is List) {
    final buffer = StringBuffer()..writeln('<array>');
    for (final item in value) {
      buffer.write(_value(item));
    }
    buffer.writeln('</array>');
    return buffer.toString();
  }
  if (value is Map<String, Object?>) return _dict(value);
  return '<string>${value ?? ''}</string>\n';
}
