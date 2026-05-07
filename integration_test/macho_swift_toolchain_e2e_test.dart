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
public protocol PermissionProtocol {
  func requestWhenInUseAuthorization()
}

public struct PermissionState: PermissionProtocol {
  public init() {}
  public func requestWhenInUseAuthorization() {
  }
}

public struct CameraPurpose {
  public let label: String
  public init(label: String) {
    self.label = label
  }
}

let value: PermissionProtocol = PermissionState()
value.requestWhenInUseAuthorization()
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
      expect(
        report.swiftProtocolConformances.map(
          (conformance) => conformance.typeName,
        ),
        contains('PermissionState'),
      );
      expect(
        report.swiftProtocolConformances.map(
          (conformance) => conformance.protocolName,
        ),
        contains('PermissionProtocol'),
      );
    },
    timeout: const Timeout(Duration(minutes: 3)),
  );
}

bool _commandExists(String command) {
  final result = Process.runSync('which', [command]);
  return result.exitCode == 0;
}
