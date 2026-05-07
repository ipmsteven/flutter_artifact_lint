import 'dart:io';

import 'package:args/args.dart';
import 'package:path/path.dart' as p;

import 'baseline.dart';
import 'formatters.dart';
import 'ios_artifact_scanner.dart';
import 'model.dart';

const version = '0.0.1';

class CliResult {
  const CliResult({required this.exitCode, this.stdout = '', this.stderr = ''});

  final int exitCode;
  final String stdout;
  final String stderr;
}

Future<CliResult> runCli(
  List<String> arguments, {
  String? workingDirectory,
}) async {
  final cwd = p.normalize(
    p.absolute(workingDirectory ?? Directory.current.path),
  );
  if (arguments.isEmpty ||
      arguments.contains('--help') ||
      arguments.contains('-h')) {
    return CliResult(exitCode: 0, stdout: _usage());
  }
  if (arguments.contains('--version')) {
    return const CliResult(
      exitCode: 0,
      stdout: 'flutter_artifact_lint 0.0.1\n',
    );
  }

  final command = arguments.first;
  if (command != 'ios') {
    return CliResult(
      exitCode: 2,
      stderr: 'Unknown command: $command\n\n${_usage()}',
    );
  }

  final parser = _iosParser();
  late final ArgResults parsed;
  try {
    parsed = parser.parse(arguments.skip(1));
  } on FormatException catch (error) {
    return CliResult(exitCode: 2, stderr: '${error.message}\n\n${_usage()}');
  }

  final format = parsed.option('format')!;
  if (format != 'text' && format != 'json') {
    return CliResult(exitCode: 2, stderr: 'Unsupported format: $format\n');
  }

  final failOn = switch (parsed.option('fail-on')) {
    'failed' => FailOn.failed,
    'warned' => FailOn.warned,
    'none' => FailOn.none,
    final value => throw StateError('Unexpected fail-on value: $value'),
  };

  try {
    if (parsed.rest.length > 1) {
      return CliResult(
        exitCode: 2,
        stderr:
            'Expected at most one artifact path, found ${parsed.rest.length}.\n\n${_usage()}',
      );
    }

    final artifact = parsed.rest.isEmpty
        ? _autoDetectArtifact(cwd)
        : p.normalize(p.absolute(cwd, parsed.rest.single));
    var scanResult = await IosArtifactScanner().scan(artifact);
    final baselinePath = parsed.option('baseline');
    if (baselinePath != null) {
      final baseline = Baseline.fromFile(
        p.normalize(p.absolute(cwd, baselinePath)),
      );
      scanResult = baseline.applyTo(scanResult);
    }
    final output = format == 'json'
        ? '${formatJson(scanResult, failOn)}\n'
        : formatText(scanResult, failOn, verbose: parsed.flag('verbose'));

    final outputPath = parsed.option('output');
    if (outputPath != null) {
      final file = File(p.normalize(p.absolute(cwd, outputPath)));
      file.parent.createSync(recursive: true);
      file.writeAsStringSync(output);
    }

    return CliResult(exitCode: scanResult.exitCodeFor(failOn), stdout: output);
  } on ArtifactScanException catch (error) {
    return CliResult(exitCode: 2, stderr: '${error.message}\n');
  } on BaselineException catch (error) {
    return CliResult(exitCode: 2, stderr: '${error.message}\n');
  } on StateError catch (error) {
    return CliResult(exitCode: 2, stderr: '${error.message}\n');
  }
}

ArgParser _iosParser() {
  return ArgParser()
    ..addOption('format', allowed: ['text', 'json'], defaultsTo: 'text')
    ..addOption(
      'fail-on',
      allowed: ['failed', 'warned', 'none'],
      defaultsTo: 'failed',
    )
    ..addOption('output')
    ..addOption('baseline')
    ..addFlag('verbose', negatable: false);
}

String _autoDetectArtifact(String cwd) {
  final candidates = <String>[];
  final appDir = Directory(p.join(cwd, 'build', 'ios', 'iphoneos'));
  if (appDir.existsSync()) {
    candidates.addAll(
      appDir
          .listSync()
          .whereType<Directory>()
          .where((dir) => dir.path.endsWith('.app'))
          .map((dir) => dir.path),
    );
  }

  final archiveDir = Directory(p.join(cwd, 'build', 'ios', 'archive'));
  if (archiveDir.existsSync()) {
    candidates.addAll(
      archiveDir
          .listSync()
          .whereType<Directory>()
          .where((dir) => dir.path.endsWith('.xcarchive'))
          .map((dir) => dir.path),
    );
  }

  if (candidates.isEmpty) {
    throw const ArtifactScanException(
      'No Flutter iOS build artifact found. Pass a .app or .xcarchive path.',
    );
  }
  if (candidates.length > 1) {
    throw ArtifactScanException(
      'Multiple Flutter iOS build artifacts found. Pass one explicitly:\n'
      '${candidates.map((candidate) => '  $candidate').join('\n')}',
    );
  }
  return candidates.single;
}

String _usage() {
  return '''
Usage:
  flutter_artifact_lint ios [artifact] [options]

Arguments:
  artifact   Path to .app or .xcarchive.
             If omitted, Flutter default build outputs are auto-detected.

Options:
  --format <text|json>           Output format (default: text)
  --fail-on <failed|warned|none> Exit policy (default: failed)
  --output <file>                Write report to file
  --baseline <file>              Suppress known findings from YAML baseline
  --verbose                      Show evidence, rule ids, and finding paths
  -h, --help                     Show help
''';
}
