import 'dart:convert';
import 'dart:io';

import 'package:flutter_artifact_lint/src/cli.dart';
import 'package:test/test.dart';

void main() {
  test(
    'auto-detects Flutter iOS app output and returns JSON with failed exit code',
    () async {
      final tempDir = await Directory.systemTemp.createTemp('fal_cli_');
      addTearDown(() => tempDir.delete(recursive: true));

      final appDir = Directory('${tempDir.path}/build/ios/iphoneos/Runner.app')
        ..createSync(recursive: true);
      File('${appDir.path}/Info.plist').writeAsStringSync(
        _plist({
          'CFBundleIdentifier': 'com.example.runner',
          'CFBundleShortVersionString': '1.2.3',
          'CFBundleVersion': '45',
          'NSCameraUsageDescription': 'TODO',
          'UILaunchStoryboardName': 'LaunchScreen',
          'UISupportedInterfaceOrientations': [
            'UIInterfaceOrientationPortrait',
          ],
          'ITSAppUsesNonExemptEncryption': false,
        }),
      );

      final result = await runCli([
        'ios',
        '--format',
        'json',
      ], workingDirectory: tempDir.path);

      expect(result.exitCode, 1);
      final payload = jsonDecode(result.stdout) as Map<String, Object?>;
      expect(payload['result'], 'FAILED');
      expect(payload['artifact'], appDir.path);
      expect(payload['failedCount'], 1);
      expect(payload['warnedCount'], 0);
    },
  );

  test(
    'does not fail on warnings by default but can fail with --fail-on warned',
    () async {
      final tempDir = await Directory.systemTemp.createTemp('fal_cli_warn_');
      addTearDown(() => tempDir.delete(recursive: true));

      final appDir = Directory('${tempDir.path}/Runner.app')..createSync();
      File('${appDir.path}/Info.plist').writeAsStringSync(
        _plist({
          'CFBundleIdentifier': 'com.example.runner',
          'CFBundleShortVersionString': '1.2.3',
          'CFBundleVersion': '45',
          'UILaunchStoryboardName': 'LaunchScreen',
          'UISupportedInterfaceOrientations': [
            'UIInterfaceOrientationPortrait',
          ],
          'ITSAppUsesNonExemptEncryption': false,
        }),
      );
      final contactsFramework = Directory(
        '${appDir.path}/Frameworks/Contacts.framework',
      )..createSync(recursive: true);
      File(
        '${contactsFramework.path}/Contacts',
      ).writeAsStringSync('CNContactStore');

      final defaultResult = await runCli([
        'ios',
        appDir.path,
      ], workingDirectory: tempDir.path);
      expect(defaultResult.exitCode, 0);
      expect(defaultResult.stdout, contains('Result    PASSED'));
      expect(defaultResult.stdout, contains('1 warned'));

      final strictResult = await runCli([
        'ios',
        appDir.path,
        '--fail-on',
        'warned',
      ], workingDirectory: tempDir.path);
      expect(strictResult.exitCode, 1);
      expect(strictResult.stdout, contains('Result    WARNED'));
    },
  );

  test('rejects multiple artifact paths with a clear CLI error', () async {
    final result = await runCli(['ios', 'one.app', 'two.app']);

    expect(result.exitCode, 2);
    expect(result.stderr, contains('Expected at most one artifact path'));
  });

  test('writes report output and creates missing parent directories', () async {
    final tempDir = await Directory.systemTemp.createTemp('fal_cli_output_');
    addTearDown(() => tempDir.delete(recursive: true));

    final appDir = Directory('${tempDir.path}/Runner.app')..createSync();
    File('${appDir.path}/Info.plist').writeAsStringSync(
      _plist({
        'CFBundleIdentifier': 'com.example.runner',
        'CFBundleShortVersionString': '1.2.3',
        'CFBundleVersion': '45',
        'UILaunchStoryboardName': 'LaunchScreen',
        'UISupportedInterfaceOrientations': ['UIInterfaceOrientationPortrait'],
        'ITSAppUsesNonExemptEncryption': false,
      }),
    );

    final result = await runCli([
      'ios',
      appDir.path,
      '--format',
      'json',
      '--output',
      'reports/ios.json',
    ], workingDirectory: tempDir.path);

    final report = File('${tempDir.path}/reports/ios.json');
    expect(result.exitCode, 0);
    expect(report.existsSync(), isTrue);
    expect(jsonDecode(report.readAsStringSync()), isA<Map>());
  });

  test('applies baseline suppressions before deciding the exit code', () async {
    final tempDir = await Directory.systemTemp.createTemp('fal_cli_baseline_');
    addTearDown(() => tempDir.delete(recursive: true));

    final appDir = Directory('${tempDir.path}/Runner.app')..createSync();
    File('${appDir.path}/Info.plist').writeAsStringSync(
      _plist({
        'CFBundleIdentifier': 'com.example.runner',
        'CFBundleShortVersionString': '1.2.3',
        'CFBundleVersion': '45',
        'NSCameraUsageDescription': 'TODO',
        'UILaunchStoryboardName': 'LaunchScreen',
        'UISupportedInterfaceOrientations': ['UIInterfaceOrientationPortrait'],
        'ITSAppUsesNonExemptEncryption': false,
      }),
    );
    File('${tempDir.path}/baseline.yml').writeAsStringSync('''
ignore:
  - ruleId: ios.permission.camera.empty
''');

    final result = await runCli([
      'ios',
      appDir.path,
      '--format',
      'json',
      '--baseline',
      'baseline.yml',
    ], workingDirectory: tempDir.path);

    final payload = jsonDecode(result.stdout) as Map<String, Object?>;
    expect(result.exitCode, 0);
    expect(payload['failedCount'], 0);
    expect(payload['suppressedCount'], 1);
  });

  test('rejects baseline entries with unknown rule ids', () async {
    final tempDir = await Directory.systemTemp.createTemp(
      'fal_cli_bad_baseline_',
    );
    addTearDown(() => tempDir.delete(recursive: true));

    final appDir = Directory('${tempDir.path}/Runner.app')..createSync();
    File('${appDir.path}/Info.plist').writeAsStringSync(
      _plist({
        'CFBundleIdentifier': 'com.example.runner',
        'CFBundleShortVersionString': '1.2.3',
        'CFBundleVersion': '45',
        'UILaunchStoryboardName': 'LaunchScreen',
        'UISupportedInterfaceOrientations': ['UIInterfaceOrientationPortrait'],
        'ITSAppUsesNonExemptEncryption': false,
      }),
    );
    File('${tempDir.path}/baseline.yml').writeAsStringSync('''
ignore:
  - ruleId: ios.permission.camra.missing
''');

    final result = await runCli([
      'ios',
      appDir.path,
      '--baseline',
      'baseline.yml',
    ], workingDirectory: tempDir.path);

    expect(result.exitCode, 2);
    expect(result.stderr, contains('Unknown baseline ruleId'));
    expect(result.stderr, contains('ios.permission.camra.missing'));
  });

  test('reports unused baseline entries without failing the scan', () async {
    final tempDir = await Directory.systemTemp.createTemp(
      'fal_cli_unused_baseline_',
    );
    addTearDown(() => tempDir.delete(recursive: true));

    final appDir = Directory('${tempDir.path}/Runner.app')..createSync();
    File('${appDir.path}/Info.plist').writeAsStringSync(
      _plist({
        'CFBundleIdentifier': 'com.example.runner',
        'CFBundleShortVersionString': '1.2.3',
        'CFBundleVersion': '45',
        'UILaunchStoryboardName': 'LaunchScreen',
        'UISupportedInterfaceOrientations': ['UIInterfaceOrientationPortrait'],
        'ITSAppUsesNonExemptEncryption': false,
      }),
    );
    File('${tempDir.path}/baseline.yml').writeAsStringSync('''
ignore:
  - ruleId: ios.permission.camera.empty
    path: Runner.app/Info.plist
''');

    final result = await runCli([
      'ios',
      appDir.path,
      '--format',
      'json',
      '--baseline',
      'baseline.yml',
    ], workingDirectory: tempDir.path);

    final payload = jsonDecode(result.stdout) as Map<String, Object?>;
    final findings = payload['findings'] as List<Object?>;

    expect(result.exitCode, 0);
    expect(payload['suppressedCount'], 0);
    expect(
      findings.cast<Map<String, Object?>>().map((finding) => finding['ruleId']),
      contains('baseline.unused'),
    );
  });

  test(
    'reports evidence source paths in JSON and verbose text output',
    () async {
      final tempDir = await Directory.systemTemp.createTemp(
        'fal_cli_evidence_',
      );
      addTearDown(() => tempDir.delete(recursive: true));

      final appDir = Directory('${tempDir.path}/Runner.app')..createSync();
      File('${appDir.path}/Info.plist').writeAsStringSync(
        _plist({
          'CFBundleIdentifier': 'com.example.runner',
          'CFBundleShortVersionString': '1.2.3',
          'CFBundleVersion': '45',
          'UILaunchStoryboardName': 'LaunchScreen',
          'UISupportedInterfaceOrientations': [
            'UIInterfaceOrientationPortrait',
          ],
          'ITSAppUsesNonExemptEncryption': false,
        }),
      );
      final contactsFramework = Directory(
        '${appDir.path}/Frameworks/Contacts.framework',
      )..createSync(recursive: true);
      final contactsBinary = File('${contactsFramework.path}/Contacts')
        ..writeAsStringSync('CNContactStore');

      final jsonResult = await runCli([
        'ios',
        appDir.path,
        '--format',
        'json',
      ], workingDirectory: tempDir.path);
      final payload = jsonDecode(jsonResult.stdout) as Map<String, Object?>;
      final findings = payload['findings'] as List<Object?>;
      final contactsFinding = findings.cast<Map<String, Object?>>().singleWhere(
        (finding) => finding['ruleId'] == 'ios.permission.contacts.missing',
      );
      final sources =
          contactsFinding['evidenceSources'] as Map<String, Object?>;

      expect(sources['CNContactStore'], contains(contactsBinary.path));

      final textResult = await runCli([
        'ios',
        appDir.path,
        '--verbose',
      ], workingDirectory: tempDir.path);

      expect(textResult.stdout, contains('Evidence Sources:'));
      expect(textResult.stdout, contains(contactsBinary.path));
    },
  );
}

String _plist(Map<String, Object?> values) {
  final buffer = StringBuffer()
    ..writeln('<?xml version="1.0" encoding="UTF-8"?>')
    ..writeln(
      '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
      '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
    )
    ..writeln('<plist version="1.0">')
    ..writeln('<dict>');

  for (final entry in values.entries) {
    buffer.writeln('<key>${entry.key}</key>');
    final value = entry.value;
    if (value is bool) {
      buffer.writeln(value ? '<true/>' : '<false/>');
    } else if (value is List<String>) {
      buffer.writeln('<array>');
      for (final item in value) {
        buffer.writeln('<string>$item</string>');
      }
      buffer.writeln('</array>');
    } else {
      buffer.writeln('<string>${value ?? ''}</string>');
    }
  }

  buffer
    ..writeln('</dict>')
    ..writeln('</plist>');
  return buffer.toString();
}
