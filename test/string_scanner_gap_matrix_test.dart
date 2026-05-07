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
  });

  group('Mach-O architecture parser acceptance', () {
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

List<int> _machOBuildVersionBytes({int platform = 2}) {
  const commandSize = 24;
  return [
    ..._machOHeaderBytes(sizeofcmds: commandSize),
    0x32, 0x00, 0x00, 0x00, // LC_BUILD_VERSION
    ..._u32(commandSize),
    ..._u32(platform),
    0x00, 0x00, 0x0c, 0x00, // minos 12.0.0
    0x00, 0x00, 0x11, 0x00, // sdk 17.0.0
    0x00, 0x00, 0x00, 0x00, // no tools
  ];
}

List<int> _machOHeaderBytes({
  int ncmds = 0,
  int sizeofcmds = 0,
  int cpuType = 0x0100000c,
}) {
  return [
    0xcf, 0xfa, 0xed, 0xfe, // MH_MAGIC_64
    ..._u32(cpuType),
    ..._u32(0), // CPU_SUBTYPE_ARM64_ALL
    ..._u32(2), // MH_EXECUTE
    ..._u32(ncmds == 0 && sizeofcmds != 0 ? 1 : ncmds),
    ..._u32(sizeofcmds),
    ..._u32(0), // flags
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

int _sourceVersion(int a, int b, int c, int d, int e) {
  return (a << 40) | (b << 30) | (c << 20) | (d << 10) | e;
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
