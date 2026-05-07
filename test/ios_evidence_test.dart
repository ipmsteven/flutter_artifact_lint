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

  test('reads fat Mach-O slices beyond the prefix window', () async {
    final root = await Directory.systemTemp.createTemp('fal_evidence_');
    addTearDown(() => root.deleteSync(recursive: true));

    final appPath = '${root.path}/Runner.app';
    final binary = File('$appPath/Runner')..createSync(recursive: true);
    binary.writeAsBytesSync(
      fatMachO([
        thinMachO([]),
        thinMachO([machoBuildVersionCommand()]),
      ], paddingBetweenSlices: 4096),
    );

    final report = const IosEvidenceExtractor(
      tokens: [],
      maxBytesPerFile: 16,
    ).collect(appPath);

    expect(
      report.architectures.expand((evidence) => evidence.architectures),
      hasLength(1),
    );
    expect(report.buildVersions, hasLength(1));
    expect(report.buildVersions.single.buildVersion.minimumOsVersion, '12.0.0');
  });
}

List<int> thinMachO(List<List<int>> commands) {
  return [
    ...u32(0xfeedfacf),
    ...u32(0x0100000c),
    ...u32(0),
    ...u32(2),
    ...u32(commands.length),
    ...u32(commands.fold(0, (total, command) => total + command.length)),
    ...u32(0),
    ...u32(0),
    for (final command in commands) ...command,
  ];
}

List<int> machoBuildVersionCommand() {
  return [
    ...u32(0x32),
    ...u32(24),
    ...u32(2),
    ...u32(0x000c0000),
    ...u32(0x00110000),
    ...u32(0),
  ];
}

List<int> fatMachO(
  List<List<int>> slices, {
  required int paddingBetweenSlices,
}) {
  const headerSize = 8;
  const archSize = 20;
  var nextOffset = headerSize + archSize * slices.length;
  final archHeaders = <int>[];
  final payload = <int>[];

  for (final slice in slices) {
    if (payload.isNotEmpty) {
      payload.addAll(List.filled(paddingBetweenSlices, 0));
      nextOffset += paddingBetweenSlices;
    }
    archHeaders
      ..addAll(u32be(0x0100000c))
      ..addAll(u32be(0))
      ..addAll(u32be(nextOffset))
      ..addAll(u32be(slice.length))
      ..addAll(u32be(0));
    payload.addAll(slice);
    nextOffset += slice.length;
  }

  return [
    ...u32be(0xcafebabe),
    ...u32be(slices.length),
    ...archHeaders,
    ...payload,
  ];
}

List<int> u32(int value) {
  return [
    value & 0xff,
    (value >> 8) & 0xff,
    (value >> 16) & 0xff,
    (value >> 24) & 0xff,
  ];
}

List<int> u32be(int value) {
  return [
    (value >> 24) & 0xff,
    (value >> 16) & 0xff,
    (value >> 8) & 0xff,
    value & 0xff,
  ];
}
