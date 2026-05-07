import 'dart:io';

import 'package:flutter_artifact_lint/src/macho.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

void main() {
  test(
    'parses Swift nominal type descriptors from a real swiftc Mach-O binary',
    () async {
      if (!Platform.isMacOS) {
        print('Skipping: swiftc Mach-O builds require macOS.');
        return;
      }
      if (!_commandExists('xcrun')) {
        print('Skipping: xcrun is not available on PATH.');
        return;
      }

      final swiftc = await Process.run('xcrun', ['--find', 'swiftc']);
      if (swiftc.exitCode != 0) {
        print('Skipping: swiftc is not available through xcrun.');
        return;
      }

      final tempDir = await Directory.systemTemp.createTemp(
        'fal_swift_macho_e2e_',
      );
      addTearDown(() => tempDir.delete(recursive: true));

      final source = File(p.join(tempDir.path, 'main.swift'))
        ..writeAsStringSync('''
public struct PermissionState {
  public let authorized: Bool
  public init(authorized: Bool) {
    self.authorized = authorized
  }
}

public struct CameraPurpose {
  public let label: String
  public init(label: String) {
    self.label = label
  }
}

let _ = PermissionState(authorized: true)
let _ = CameraPurpose(label: "camera")
''');
      final binary = File(p.join(tempDir.path, 'SwiftFixture'));
      final build = await Process.run('xcrun', [
        'swiftc',
        source.path,
        '-o',
        binary.path,
      ]).timeout(const Duration(minutes: 2));
      expect(
        build.exitCode,
        0,
        reason: 'swiftc failed\n${build.stdout}\n${build.stderr}',
      );

      final report = const MachOParser().parseFile(binary);

      expect(
        report.swiftTypes.map((swiftType) => swiftType.name),
        containsAll(['PermissionState', 'CameraPurpose']),
      );
    },
    timeout: const Timeout(Duration(minutes: 3)),
  );
}

bool _commandExists(String command) {
  final result = Process.runSync('which', [command]);
  return result.exitCode == 0;
}
