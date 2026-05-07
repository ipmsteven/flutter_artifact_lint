import 'dart:io';

import 'package:flutter_artifact_lint/src/ios_evidence.dart';
import 'package:test/test.dart';

void main() {
  test('streams text evidence beyond the Mach-O prefix window', () async {
    final root = await Directory.systemTemp.createTemp('fal_evidence_');
    addTearDown(() => root.deleteSync(recursive: true));

    final appPath = '${root.path}/Runner.app';
    final binary = File('$appPath/Frameworks/Large.framework/Large')
      ..createSync(recursive: true);
    binary.writeAsStringSync('${'A' * 4096}AVCaptureSession');

    final report = const IosEvidenceExtractor(
      tokens: ['AVCaptureSession'],
      maxBytesPerFile: 16,
    ).collect(appPath);

    expect(report.tokens, contains('AVCaptureSession'));
    expect(
      report.sourcesFor(['AVCaptureSession'])['AVCaptureSession'],
      contains(binary.path),
    );
  });
}
