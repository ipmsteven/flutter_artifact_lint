import 'dart:io';

import 'package:flutter_artifact_lint/src/cli.dart';

Future<void> main(List<String> arguments) async {
  final result = await runCli(arguments);
  if (result.stdout.isNotEmpty) stdout.write(result.stdout);
  if (result.stderr.isNotEmpty) stderr.write(result.stderr);
  exitCode = result.exitCode;
}
