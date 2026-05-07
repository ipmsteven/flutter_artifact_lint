import 'dart:io';

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

  test('documents every registered rule in docs/rules.md', () {
    final docs = File('docs/rules.md').readAsStringSync();

    for (final ruleId in ruleRegistry.keys) {
      expect(docs, contains('`$ruleId`'), reason: '$ruleId is undocumented');
    }
  });
}
