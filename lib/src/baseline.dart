import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:yaml/yaml.dart';

import 'model.dart';
import 'rules.dart';

class BaselineException implements Exception {
  const BaselineException(this.message);

  final String message;

  @override
  String toString() => message;
}

class Baseline {
  const Baseline(this.entries);

  final List<BaselineEntry> entries;

  static Baseline fromFile(String path) {
    final file = File(path);
    if (!file.existsSync()) {
      throw BaselineException('Baseline file does not exist: $path');
    }

    late final Object? document;
    try {
      document = loadYaml(file.readAsStringSync());
    } catch (error) {
      throw BaselineException('Baseline file is not valid YAML: $error');
    }

    if (document == null) return const Baseline([]);
    if (document is! YamlMap) {
      throw const BaselineException('Baseline root must be a YAML map.');
    }

    final ignore = document['ignore'];
    if (ignore == null) return const Baseline([]);
    if (ignore is! YamlList) {
      throw const BaselineException('Baseline ignore must be a YAML list.');
    }

    final entries = ignore.map(_entryFromYaml).toList();
    for (final entry in entries) {
      if (!isKnownRule(entry.ruleId)) {
        throw BaselineException('Unknown baseline ruleId: ${entry.ruleId}');
      }
    }

    return Baseline(entries);
  }

  ScanResult applyTo(ScanResult result) {
    final kept = <LintFinding>[];
    final matchedEntries = <BaselineEntry>{};
    var suppressed = 0;

    for (final finding in result.findings) {
      final matched = entries.where((entry) => entry.matches(finding)).toList();
      if (matched.isNotEmpty) {
        matchedEntries.addAll(matched);
        suppressed++;
      } else {
        kept.add(finding);
      }
    }

    for (final entry in entries) {
      if (matchedEntries.contains(entry)) continue;
      kept.add(
        buildFinding(
          'baseline.unused',
          message: 'Baseline entry did not match any finding: ${entry.label}.',
        ),
      );
    }

    return result.copyWith(
      findings: kept,
      suppressedCount: result.suppressedCount + suppressed,
    );
  }

  static BaselineEntry _entryFromYaml(Object? value) {
    if (value is String) return BaselineEntry(ruleId: value);
    if (value is! YamlMap) {
      throw const BaselineException(
        'Each baseline ignore entry must be a rule id or a map.',
      );
    }

    final ruleId = value['ruleId'];
    if (ruleId is! String || ruleId.trim().isEmpty) {
      throw const BaselineException(
        'Each baseline ignore map must contain ruleId.',
      );
    }

    final path = value['path'];
    if (path != null && path is! String) {
      throw const BaselineException('Baseline ignore path must be a string.');
    }

    return BaselineEntry(ruleId: ruleId, path: path);
  }
}

class BaselineEntry {
  const BaselineEntry({required this.ruleId, this.path});

  final String ruleId;
  final String? path;

  String get label => path == null ? ruleId : '$ruleId ($path)';

  bool matches(LintFinding finding) {
    if (finding.ruleId != ruleId) return false;
    final expectedPath = path;
    if (expectedPath == null) return true;

    final findingPath = finding.path;
    if (findingPath == null) return false;
    return _normalize(findingPath).endsWith(_normalize(expectedPath));
  }
}

String _normalize(String path) {
  return p.normalize(path).replaceAll('\\', '/');
}
