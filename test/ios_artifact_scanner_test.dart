import 'dart:io';

import 'package:flutter_artifact_lint/src/ios_artifact_scanner.dart';
import 'package:test/test.dart';

void main() {
  test(
    'scans an unsigned Flutter app artifact into failed warned and info findings',
    () async {
      final tempDir = await Directory.systemTemp.createTemp('fal_scanner_');
      addTearDown(() => tempDir.delete(recursive: true));

      final appDir = Directory('${tempDir.path}/Runner.app')..createSync();
      File('${appDir.path}/Info.plist').writeAsStringSync(
        _plist({
          'CFBundleIdentifier': 'com.example.runner',
          'CFBundleShortVersionString': '1.2.3',
          'CFBundleVersion': '45',
          'NSCameraUsageDescription': '',
          'UILaunchStoryboardName': 'LaunchScreen',
          'UISupportedInterfaceOrientations': [
            'UIInterfaceOrientationPortrait',
          ],
          'ITSAppUsesNonExemptEncryption': false,
        }),
      );
      File(
        '${appDir.path}/PrivacyInfo.xcprivacy',
      ).writeAsStringSync('not a plist');

      final contactsFramework = Directory(
        '${appDir.path}/Frameworks/Contacts.framework',
      )..createSync(recursive: true);
      File(
        '${contactsFramework.path}/Contacts',
      ).writeAsStringSync('CNContactStore');

      final result = await IosArtifactScanner().scan(appDir.path);

      expect(result.artifact.path, appDir.path);
      expect(result.artifact.type.name, 'unsignedApp');
      expect(
        result.failed.map((f) => f.ruleId),
        contains('ios.permission.camera.empty'),
      );
      expect(
        result.failed.map((f) => f.ruleId),
        contains('ios.privacy_manifest.invalid'),
      );
      expect(
        result.warned.map((f) => f.ruleId),
        contains('ios.permission.contacts.missing'),
      );
      expect(
        result.info.map((f) => f.ruleId),
        contains('ios.bundle.identifier'),
      );
      expect(
        result.info.map((f) => f.ruleId),
        contains('ios.signing.unavailable'),
      );
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
