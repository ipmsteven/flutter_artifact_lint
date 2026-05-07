import 'dart:convert';

import 'model.dart';

String formatJson(ScanResult result, FailOn failOn) {
  return const JsonEncoder.withIndent('  ').convert(result.toJson(failOn));
}

String formatText(ScanResult result, FailOn failOn, {bool verbose = false}) {
  final buffer = StringBuffer()
    ..writeln('Flutter Artifact Lint iOS')
    ..writeln()
    ..writeln('Artifact  ${result.artifact.path}')
    ..writeln('Type      ${result.artifact.displayType}')
    ..writeln()
    ..writeln('Result    ${result.resultFor(failOn)}')
    ..writeln(
      '          ${_count(result.failed.length, 'failed')}, '
      '${_count(result.warned.length, 'warned')}, '
      '${_count(result.info.length, 'info')}, '
      '${_count(result.suppressedCount, 'suppressed')}',
    );

  _writeSection(buffer, 'Failed', result.failed, verbose: verbose);
  _writeSection(buffer, 'Warned', result.warned, verbose: verbose);

  if (verbose || result.failed.isNotEmpty) {
    _writeSection(buffer, 'Info', result.info, verbose: verbose);
  } else if (result.info.isNotEmpty) {
    buffer
      ..writeln()
      ..writeln('Run with --verbose to see artifact inventory.');
  }

  return buffer.toString();
}

void _writeSection(
  StringBuffer buffer,
  String title,
  List<LintFinding> findings, {
  required bool verbose,
}) {
  if (findings.isEmpty) return;
  buffer
    ..writeln()
    ..writeln(title)
    ..writeln();

  for (final finding in findings) {
    buffer
      ..writeln('  ${finding.title}')
      ..writeln('  ${finding.message}');
    if (finding.fix != null) {
      buffer.writeln('  Fix: ${finding.fix}');
    }
    if (verbose) {
      buffer.writeln('  Rule: ${finding.ruleId}');
      if (finding.path != null) buffer.writeln('  Path: ${finding.path}');
      if (finding.evidence.isNotEmpty) {
        buffer.writeln('  Evidence: ${finding.evidence.join(', ')}');
      }
    }
    buffer.writeln();
  }
}

String _count(int value, String noun) => '$value $noun';
