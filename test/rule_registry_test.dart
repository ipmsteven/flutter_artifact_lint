import 'dart:io';

import 'package:flutter_artifact_lint/src/ios_artifact_scanner.dart';
import 'package:flutter_artifact_lint/src/model.dart';
import 'package:flutter_artifact_lint/src/rules.dart';
import 'package:test/test.dart';

void main() {
  test('registers every public iOS rule id with documentation metadata', () {
    expect(ruleRegistry, isNotEmpty);

    for (final entry in ruleRegistry.entries) {
      expect(entry.key, entry.value.ruleId);
      expect(entry.value.title.trim(), isNotEmpty);
      expect(entry.value.description.trim(), isNotEmpty);
      expect(entry.value.fix.trim(), isNotEmpty);
      expect(entry.value.source.name, isNotEmpty);
      expect(entry.value.confidence.name, isNotEmpty);
    }
  });

  test('documents every registered rule in doc/rules.md', () {
    final docs = File('doc/rules.md').readAsStringSync();

    for (final ruleId in ruleRegistry.keys) {
      expect(docs, contains('`$ruleId`'), reason: '$ruleId is undocumented');
    }
  });

  test(
    'scanner findings use RuleRegistry level title and fix metadata',
    () async {
      final tempDir = await Directory.systemTemp.createTemp('fal_registry_');
      addTearDown(() => tempDir.delete(recursive: true));

      final appDir = Directory('${tempDir.path}/Runner.app')..createSync();
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
      final contactsFramework = Directory(
        '${appDir.path}/Frameworks/Contacts.framework',
      )..createSync(recursive: true);
      File(
        '${contactsFramework.path}/Contacts',
      ).writeAsStringSync('CNContactStore');

      final result = await IosArtifactScanner().scan(appDir.path);

      for (final finding in result.findings) {
        final rule = ruleRegistry[finding.ruleId]!;
        expect(finding.level, rule.defaultLevel, reason: finding.ruleId);
        expect(finding.title, rule.title, reason: finding.ruleId);
        if (finding.level != FindingLevel.info) {
          expect(finding.fix, rule.fix, reason: finding.ruleId);
        }
      }
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
