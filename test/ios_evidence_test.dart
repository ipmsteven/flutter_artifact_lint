import 'dart:convert';
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

  test('reports parsed Mach-O section sources for token evidence', () async {
    final root = await Directory.systemTemp.createTemp('fal_evidence_');
    addTearDown(() => root.deleteSync(recursive: true));

    final appPath = '${root.path}/Runner.app';
    final binary = File('$appPath/Runner')..createSync(recursive: true);
    binary.writeAsBytesSync(
      thinMachOWithCStringSection(
        sectionName: '__objc_methname',
        values: ['requestWhenInUseAuthorization'],
      ),
    );

    final report = const IosEvidenceExtractor(
      tokens: ['requestWhenInUseAuthorization'],
    ).collect(appPath);

    expect(
      report.sourcesFor([
        'requestWhenInUseAuthorization',
      ])['requestWhenInUseAuthorization'],
      contains('${binary.path}#__TEXT.__objc_methname'),
    );
  });

  test(
    'reports parsed Mach-O symbol table sources for token evidence',
    () async {
      final root = await Directory.systemTemp.createTemp('fal_evidence_');
      addTearDown(() => root.deleteSync(recursive: true));

      final appPath = '${root.path}/Runner.app';
      final binary = File('$appPath/Runner')..createSync(recursive: true);
      binary.writeAsBytesSync(
        thinMachOWithSymbolTable(['_UIApplicationOpenSettingsURLString']),
      );

      final report = const IosEvidenceExtractor(
        tokens: ['_UIApplicationOpenSettingsURLString'],
      ).collect(appPath);

      expect(
        report.sourcesFor([
          '_UIApplicationOpenSettingsURLString',
        ])['_UIApplicationOpenSettingsURLString'],
        contains('${binary.path}#LC_SYMTAB'),
      );
    },
  );

  test(
    'reports parsed Objective-C selector reference sources for token evidence',
    () async {
      final root = await Directory.systemTemp.createTemp('fal_evidence_');
      addTearDown(() => root.deleteSync(recursive: true));

      final appPath = '${root.path}/Runner.app';
      final binary = File('$appPath/Runner')..createSync(recursive: true);
      binary.writeAsBytesSync(
        thinMachOWithObjCSelectorRefs(['requestWhenInUseAuthorization']),
      );

      final report = const IosEvidenceExtractor(
        tokens: ['requestWhenInUseAuthorization'],
      ).collect(appPath);

      expect(
        report.sourcesFor([
          'requestWhenInUseAuthorization',
        ])['requestWhenInUseAuthorization'],
        contains('${binary.path}#__DATA_CONST.__objc_selrefs'),
      );
    },
  );
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

List<int> thinMachOWithCStringSection({
  required String sectionName,
  required List<String> values,
}) {
  final sectionData = cStringBytes(values);
  final commandSize = 72 + 80;
  final sectionOffset = 32 + commandSize;
  final command = machoSegment64Command('__TEXT', [
    (
      name: sectionName,
      segmentName: '__TEXT',
      fileOffset: sectionOffset,
      size: sectionData.length,
    ),
  ]);

  return [
    ...u32(0xfeedfacf),
    ...u32(0x0100000c),
    ...u32(0),
    ...u32(2),
    ...u32(1),
    ...u32(command.length),
    ...u32(0),
    ...u32(0),
    ...command,
    ...sectionData,
  ];
}

List<int> thinMachOWithSymbolTable(List<String> symbols) {
  final stringTable = [
    0,
    for (final symbol in symbols) ...[...latin1.encode(symbol), 0],
  ];
  final symbolEntries = <int>[];
  var stringIndex = 1;
  for (final symbol in symbols) {
    symbolEntries.addAll([
      ...u32(stringIndex),
      0x0f,
      0x01,
      ...u16(0),
      ...u64(0),
    ]);
    stringIndex += latin1.encode(symbol).length + 1;
  }

  const commandSize = 24;
  const symbolOffset = 32 + commandSize;
  final stringOffset = symbolOffset + symbolEntries.length;
  return [
    ...u32(0xfeedfacf),
    ...u32(0x0100000c),
    ...u32(0),
    ...u32(2),
    ...u32(1),
    ...u32(commandSize),
    ...u32(0),
    ...u32(0),
    ...u32(0x02),
    ...u32(commandSize),
    ...u32(symbolOffset),
    ...u32(symbols.length),
    ...u32(stringOffset),
    ...u32(stringTable.length),
    ...symbolEntries,
    ...stringTable,
  ];
}

List<int> thinMachOWithObjCSelectorRefs(List<String> selectors) {
  final methnameAddress = 0x100000100;
  final selrefsAddress = 0x100000800;
  final methnameData = cStringBytes(selectors);
  final selectorOffsets = stringOffsets(selectors);
  final pointerData = [
    for (final selectorOffset in selectorOffsets)
      ...u64(methnameAddress + selectorOffset),
  ];
  final commandsSize = 2 * (72 + 80);
  final methnameOffset = 32 + commandsSize;
  final selrefsOffset = methnameOffset + methnameData.length;
  final textCommand = machoSegment64AddressCommand('__TEXT', [
    (
      name: '__objc_methname',
      segmentName: '__TEXT',
      address: methnameAddress,
      fileOffset: methnameOffset,
      size: methnameData.length,
    ),
  ]);
  final dataCommand = machoSegment64AddressCommand('__DATA_CONST', [
    (
      name: '__objc_selrefs',
      segmentName: '__DATA_CONST',
      address: selrefsAddress,
      fileOffset: selrefsOffset,
      size: pointerData.length,
    ),
  ]);

  return [
    ...u32(0xfeedfacf),
    ...u32(0x0100000c),
    ...u32(0),
    ...u32(2),
    ...u32(2),
    ...u32(textCommand.length + dataCommand.length),
    ...u32(0),
    ...u32(0),
    ...textCommand,
    ...dataCommand,
    ...methnameData,
    ...pointerData,
  ];
}

List<int> machoSegment64Command(
  String segmentName,
  List<({String name, String segmentName, int fileOffset, int size})> sections,
) {
  return machoSegment64AddressCommand(segmentName, [
    for (final section in sections)
      (
        name: section.name,
        segmentName: section.segmentName,
        address: 0,
        fileOffset: section.fileOffset,
        size: section.size,
      ),
  ]);
}

List<int> machoSegment64AddressCommand(
  String segmentName,
  List<
    ({String name, String segmentName, int address, int fileOffset, int size})
  >
  sections,
) {
  return [
    ...u32(0x19),
    ...u32(72 + sections.length * 80),
    ...fixedString(segmentName, 16),
    ...u64(0),
    ...u64(0),
    ...u64(0),
    ...u64(0),
    ...u32(0),
    ...u32(0),
    ...u32(sections.length),
    ...u32(0),
    for (final section in sections) ...[
      ...fixedString(section.name, 16),
      ...fixedString(section.segmentName, 16),
      ...u64(section.address),
      ...u64(section.size),
      ...u32(section.fileOffset),
      ...u32(0),
      ...u32(0),
      ...u32(0),
      ...u32(0),
      ...u32(0),
      ...u32(0),
      ...u32(0),
    ],
  ];
}

List<int> cStringBytes(List<String> values) {
  return [
    for (final value in values) ...[...latin1.encode(value), 0],
  ];
}

List<int> stringOffsets(List<String> values) {
  final offsets = <int>[];
  var offset = 0;
  for (final value in values) {
    offsets.add(offset);
    offset += latin1.encode(value).length + 1;
  }
  return offsets;
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

List<int> u16(int value) {
  return [value & 0xff, (value >> 8) & 0xff];
}

List<int> u32be(int value) {
  return [
    (value >> 24) & 0xff,
    (value >> 16) & 0xff,
    (value >> 8) & 0xff,
    value & 0xff,
  ];
}

List<int> u64(int value) {
  return [
    value & 0xff,
    (value >> 8) & 0xff,
    (value >> 16) & 0xff,
    (value >> 24) & 0xff,
    (value >> 32) & 0xff,
    (value >> 40) & 0xff,
    (value >> 48) & 0xff,
    (value >> 56) & 0xff,
  ];
}

List<int> fixedString(String value, int length) {
  final bytes = latin1.encode(value);
  return [
    ...bytes.take(length),
    ...List.filled(length - (bytes.length > length ? length : bytes.length), 0),
  ];
}
