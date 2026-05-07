import 'dart:convert';
import 'dart:io';

import 'package:flutter_artifact_lint/src/cli.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

void main() {
  test(
    'fails a real Flutter iOS release build with an invalid camera purpose string',
    () async {
      if (!Platform.isMacOS) {
        print('Skipping: iOS Flutter builds require macOS.');
        return;
      }
      if (!_commandExists('flutter')) {
        print('Skipping: flutter is not available on PATH.');
        return;
      }
      if (!_commandExists('xcodebuild')) {
        print('Skipping: xcodebuild is not available on PATH.');
        return;
      }

      final tempDir = await Directory.systemTemp.createTemp(
        'fal_flutter_ios_e2e_',
      );
      addTearDown(() => tempDir.delete(recursive: true));

      final create = await Process.run('flutter', [
        'create',
        '--platforms=ios',
        '--project-name',
        'e2e_app',
        '--org',
        'com.example',
        '.',
      ], workingDirectory: tempDir.path);
      expect(
        create.exitCode,
        0,
        reason: 'flutter create failed\n${create.stdout}\n${create.stderr}',
      );

      final plistPath = p.join(tempDir.path, 'ios', 'Runner', 'Info.plist');
      final plist = File(plistPath);
      final plistContent = plist.readAsStringSync();
      final rootDictEnd = plistContent.lastIndexOf('</dict>');
      expect(rootDictEnd, greaterThan(0));
      plist.writeAsStringSync('''
${plistContent.substring(0, rootDictEnd)}
	<key>NSCameraUsageDescription</key>
	<string>TODO</string>
</dict>
${plistContent.substring(rootDictEnd + '</dict>'.length)}''');
      expect(plist.readAsStringSync(), contains('NSCameraUsageDescription'));

      final build = await Process.run('flutter', [
        'build',
        'ios',
        '--release',
        '--no-tree-shake-icons',
        '--no-codesign',
      ], workingDirectory: tempDir.path).timeout(const Duration(minutes: 10));
      expect(
        build.exitCode,
        0,
        reason: 'flutter build ios failed\n${build.stdout}\n${build.stderr}',
      );

      final result = await runCli([
        'ios',
        '--format',
        'json',
      ], workingDirectory: tempDir.path);

      expect(result.exitCode, 1);
      final payload = jsonDecode(result.stdout) as Map<String, Object?>;
      expect(payload['result'], 'FAILED');
      final findings = payload['findings'] as List<Object?>;
      final ruleIds = findings.cast<Map<String, Object?>>().map(
        (finding) => finding['ruleId'],
      );
      expect(ruleIds, contains('ios.permission.camera.empty'));
      expect(ruleIds, contains('ios.macho.architecture'));
      expect(ruleIds, contains('ios.macho.build_version'));
    },
    timeout: const Timeout(Duration(minutes: 12)),
  );
}

bool _commandExists(String command) {
  final result = Process.runSync('which', [command]);
  return result.exitCode == 0;
}
