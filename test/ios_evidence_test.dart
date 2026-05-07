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
    'reports parsed Swift metadata section sources for token evidence',
    () async {
      final root = await Directory.systemTemp.createTemp('fal_evidence_');
      addTearDown(() => root.deleteSync(recursive: true));

      final appPath = '${root.path}/Runner.app';
      final binary = File('$appPath/Runner')..createSync(recursive: true);
      binary.writeAsBytesSync(
        thinMachOWithCStringSection(
          sectionName: '__swift5_reflstr',
          values: ['cameraUsageDescription'],
        ),
      );

      final report = const IosEvidenceExtractor(
        tokens: ['cameraUsageDescription'],
      ).collect(appPath);

      expect(
        report.sourcesFor(['cameraUsageDescription'])['cameraUsageDescription'],
        contains('${binary.path}#__TEXT.__swift5_reflstr'),
      );
    },
  );

  test(
    'reports parsed Swift type descriptor sources for token evidence',
    () async {
      final root = await Directory.systemTemp.createTemp('fal_evidence_');
      addTearDown(() => root.deleteSync(recursive: true));

      final appPath = '${root.path}/Runner.app';
      final binary = File('$appPath/Runner')..createSync(recursive: true);
      binary.writeAsBytesSync(
        thinMachOWithSwiftTypeDescriptors(['PermissionState']),
      );

      final report = const IosEvidenceExtractor(
        tokens: ['PermissionState'],
      ).collect(appPath);

      expect(
        report.sourcesFor(['PermissionState'])['PermissionState'],
        contains('${binary.path}#__TEXT.__swift5_types'),
      );
    },
  );

  test(
    'reports parsed Swift protocol conformance sources for token evidence',
    () async {
      final root = await Directory.systemTemp.createTemp('fal_evidence_');
      addTearDown(() => root.deleteSync(recursive: true));

      final appPath = '${root.path}/Runner.app';
      final binary = File('$appPath/Runner')..createSync(recursive: true);
      binary.writeAsBytesSync(
        thinMachOWithSwiftProtocolConformances([
          (typeName: 'PermissionState', protocolName: 'PermissionProtocol'),
        ]),
      );

      final report = const IosEvidenceExtractor(
        tokens: ['PermissionProtocol'],
      ).collect(appPath);

      expect(
        report.sourcesFor(['PermissionProtocol'])['PermissionProtocol'],
        contains('${binary.path}#__TEXT.__swift5_proto'),
      );
    },
  );

  test(
    'reports parsed Swift protocol descriptor sources for token evidence',
    () async {
      final root = await Directory.systemTemp.createTemp('fal_evidence_');
      addTearDown(() => root.deleteSync(recursive: true));

      final appPath = '${root.path}/Runner.app';
      final binary = File('$appPath/Runner')..createSync(recursive: true);
      binary.writeAsBytesSync(
        thinMachOWithSwiftProtocolDescriptors(['PermissionProtocol']),
      );

      final report = const IosEvidenceExtractor(
        tokens: ['PermissionProtocol'],
      ).collect(appPath);

      expect(
        report.sourcesFor(['PermissionProtocol'])['PermissionProtocol'],
        contains('${binary.path}#__TEXT.__swift5_protos'),
      );
    },
  );

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

  test('reports parsed dyld bind symbol sources for token evidence', () async {
    final root = await Directory.systemTemp.createTemp('fal_evidence_');
    addTearDown(() => root.deleteSync(recursive: true));

    final appPath = '${root.path}/Runner.app';
    final binary = File('$appPath/Runner')..createSync(recursive: true);
    binary.writeAsBytesSync(
      thinMachOWithDyldBindSymbols([r'_OBJC_CLASS_$_CLLocationManager']),
    );

    final report = const IosEvidenceExtractor(
      tokens: ['CLLocationManager'],
    ).collect(appPath);

    expect(
      report.sourcesFor(['CLLocationManager'])['CLLocationManager'],
      contains('${binary.path}#LC_DYLD_INFO.bind'),
    );
  });

  test(
    'reports parsed chained fixup import sources for token evidence',
    () async {
      final root = await Directory.systemTemp.createTemp('fal_evidence_');
      addTearDown(() => root.deleteSync(recursive: true));

      final appPath = '${root.path}/Runner.app';
      final binary = File('$appPath/Runner')..createSync(recursive: true);
      binary.writeAsBytesSync(
        thinMachOWithChainedFixupImports([
          r'_OBJC_CLASS_$_UNUserNotificationCenter',
        ]),
      );

      final report = const IosEvidenceExtractor(
        tokens: ['UNUserNotificationCenter'],
      ).collect(appPath);

      expect(
        report.sourcesFor([
          'UNUserNotificationCenter',
        ])['UNUserNotificationCenter'],
        contains('${binary.path}#LC_DYLD_CHAINED_FIXUPS.imports'),
      );
    },
  );

  test('reports parsed exports trie sources for token evidence', () async {
    final root = await Directory.systemTemp.createTemp('fal_evidence_');
    addTearDown(() => root.deleteSync(recursive: true));

    final appPath = '${root.path}/Runner.app';
    final binary = File('$appPath/Runner')..createSync(recursive: true);
    binary.writeAsBytesSync(
      thinMachOWithDyldExportsTrie(['_UIApplicationOpenSettingsURLString']),
    );

    final report = const IosEvidenceExtractor(
      tokens: ['_UIApplicationOpenSettingsURLString'],
    ).collect(appPath);

    expect(
      report.sourcesFor([
        '_UIApplicationOpenSettingsURLString',
      ])['_UIApplicationOpenSettingsURLString'],
      contains('${binary.path}#LC_DYLD_EXPORTS_TRIE'),
    );
  });

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

  test(
    'reports parsed Objective-C class reference sources for token evidence',
    () async {
      final root = await Directory.systemTemp.createTemp('fal_evidence_');
      addTearDown(() => root.deleteSync(recursive: true));

      final appPath = '${root.path}/Runner.app';
      final binary = File('$appPath/Runner')..createSync(recursive: true);
      binary.writeAsBytesSync(thinMachOWithObjCClassRef('CLLocationManager'));

      final report = const IosEvidenceExtractor(
        tokens: ['CLLocationManager'],
      ).collect(appPath);

      expect(
        report.sourcesFor(['CLLocationManager'])['CLLocationManager'],
        contains('${binary.path}#__DATA_CONST.__objc_classrefs'),
      );
    },
  );

  test(
    'reports parsed Objective-C protocol reference sources for token evidence',
    () async {
      final root = await Directory.systemTemp.createTemp('fal_evidence_');
      addTearDown(() => root.deleteSync(recursive: true));

      final appPath = '${root.path}/Runner.app';
      final binary = File('$appPath/Runner')..createSync(recursive: true);
      binary.writeAsBytesSync(
        thinMachOWithObjCProtocolRefs([
          'FlutterPlugin',
        ], sectionName: '__objc_protorefs'),
      );

      final report = const IosEvidenceExtractor(
        tokens: ['FlutterPlugin'],
      ).collect(appPath);

      expect(
        report.sourcesFor(['FlutterPlugin'])['FlutterPlugin'],
        contains('${binary.path}#__DATA_CONST.__objc_protorefs'),
      );
    },
  );

  test(
    'reports parsed Objective-C method list sources for token evidence',
    () async {
      final root = await Directory.systemTemp.createTemp('fal_evidence_');
      addTearDown(() => root.deleteSync(recursive: true));

      final appPath = '${root.path}/Runner.app';
      final binary = File('$appPath/Runner')..createSync(recursive: true);
      binary.writeAsBytesSync(
        thinMachOWithObjCMethodList(
          className: 'RunnerViewController',
          methodNames: ['requestWhenInUseAuthorization'],
        ),
      );

      final report = const IosEvidenceExtractor(
        tokens: ['requestWhenInUseAuthorization'],
      ).collect(appPath);

      expect(
        report.sourcesFor([
          'requestWhenInUseAuthorization',
        ])['requestWhenInUseAuthorization'],
        contains('${binary.path}#__DATA_CONST.__objc_const'),
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

List<int> thinMachOWithSwiftTypeDescriptors(List<String> typeNames) {
  final typesAddress = 0x100000100;
  final descriptorAddress = 0x100001000;
  final descriptorData = <int>[];
  final typeEntries = <int>[];

  for (var i = 0; i < typeNames.length; i += 1) {
    final entryAddress = typesAddress + i * 4;
    final currentDescriptorAddress = descriptorAddress + descriptorData.length;
    final nameAddress = currentDescriptorAddress + 16;
    typeEntries.addAll(u32(currentDescriptorAddress - entryAddress));
    descriptorData.addAll([
      ...u32(0),
      ...u32(0),
      ...u32(nameAddress - (currentDescriptorAddress + 8)),
      ...u32(0),
      ...latin1.encode(typeNames[i]),
      0,
    ]);
  }

  final commandSize = 72 + 2 * 80;
  final typesOffset = 32 + commandSize;
  final descriptorOffset = typesOffset + typeEntries.length;
  final command = machoSegment64AddressCommand('__TEXT', [
    (
      name: '__swift5_types',
      segmentName: '__TEXT',
      address: typesAddress,
      fileOffset: typesOffset,
      size: typeEntries.length,
    ),
    (
      name: '__const',
      segmentName: '__TEXT',
      address: descriptorAddress,
      fileOffset: descriptorOffset,
      size: descriptorData.length,
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
    ...typeEntries,
    ...descriptorData,
  ];
}

List<int> thinMachOWithSwiftProtocolConformances(
  List<({String typeName, String protocolName})> conformances,
) {
  final protoAddress = 0x100000100;
  final descriptorAddress = 0x100001000;
  final descriptorData = <int>[];
  final protoEntries = <int>[];

  for (var i = 0; i < conformances.length; i += 1) {
    final entryAddress = protoAddress + i * 4;
    final currentConformanceAddress = descriptorAddress + descriptorData.length;
    final typeDescriptorAddress = currentConformanceAddress + 16;
    final typeNameAddress = typeDescriptorAddress + 16;
    final protocolDescriptorAddress =
        typeNameAddress + latin1.encode(conformances[i].typeName).length + 1;
    final protocolNameAddress = protocolDescriptorAddress + 16;
    protoEntries.addAll(u32(currentConformanceAddress - entryAddress));
    descriptorData.addAll([
      ...u32(protocolDescriptorAddress - currentConformanceAddress),
      ...u32(typeDescriptorAddress - (currentConformanceAddress + 4)),
      ...u32(0),
      ...u32(0),
      ...u32(0),
      ...u32(0),
      ...u32(typeNameAddress - (typeDescriptorAddress + 8)),
      ...u32(0),
      ...latin1.encode(conformances[i].typeName),
      0,
      ...u32(0),
      ...u32(0),
      ...u32(protocolNameAddress - (protocolDescriptorAddress + 8)),
      ...u32(0),
      ...latin1.encode(conformances[i].protocolName),
      0,
    ]);
  }

  final commandSize = 72 + 2 * 80;
  final protoOffset = 32 + commandSize;
  final descriptorOffset = protoOffset + protoEntries.length;
  final command = machoSegment64AddressCommand('__TEXT', [
    (
      name: '__swift5_proto',
      segmentName: '__TEXT',
      address: protoAddress,
      fileOffset: protoOffset,
      size: protoEntries.length,
    ),
    (
      name: '__const',
      segmentName: '__TEXT',
      address: descriptorAddress,
      fileOffset: descriptorOffset,
      size: descriptorData.length,
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
    ...protoEntries,
    ...descriptorData,
  ];
}

List<int> thinMachOWithSwiftProtocolDescriptors(List<String> protocolNames) {
  final protosAddress = 0x100000100;
  final descriptorAddress = 0x100001000;
  final descriptorData = <int>[];
  final protoEntries = <int>[];

  for (var i = 0; i < protocolNames.length; i += 1) {
    final entryAddress = protosAddress + i * 4;
    final currentDescriptorAddress = descriptorAddress + descriptorData.length;
    final nameAddress = currentDescriptorAddress + 16;
    protoEntries.addAll(u32(currentDescriptorAddress - entryAddress));
    descriptorData.addAll([
      ...u32(0),
      ...u32(0),
      ...u32(nameAddress - (currentDescriptorAddress + 8)),
      ...u32(0),
      ...latin1.encode(protocolNames[i]),
      0,
    ]);
  }

  final commandSize = 72 + 2 * 80;
  final protosOffset = 32 + commandSize;
  final descriptorOffset = protosOffset + protoEntries.length;
  final command = machoSegment64AddressCommand('__TEXT', [
    (
      name: '__swift5_protos',
      segmentName: '__TEXT',
      address: protosAddress,
      fileOffset: protosOffset,
      size: protoEntries.length,
    ),
    (
      name: '__const',
      segmentName: '__TEXT',
      address: descriptorAddress,
      fileOffset: descriptorOffset,
      size: descriptorData.length,
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
    ...protoEntries,
    ...descriptorData,
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

List<int> thinMachOWithDyldBindSymbols(List<String> symbols) {
  final bindInfo = dyldBindInfoBytes(symbols);
  const commandsSize = 48;
  final bindOffset = 32 + commandsSize;
  final command = machoDyldInfoCommand(
    bindOffset: bindOffset,
    bindSize: bindInfo.length,
  );

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
    ...bindInfo,
  ];
}

List<int> thinMachOWithChainedFixupImports(List<String> symbols) {
  final chainedFixups = chainedFixupsPayload(symbols);
  const commandsSize = 16;
  final dataOffset = 32 + commandsSize;
  final command = machoChainedFixupsCommand(
    dataOffset: dataOffset,
    dataSize: chainedFixups.length,
  );

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
    ...chainedFixups,
  ];
}

List<int> thinMachOWithDyldExportsTrie(List<String> symbols) {
  final exportsTrie = dyldExportsTrieBytes(symbols);
  const commandsSize = 16;
  final dataOffset = 32 + commandsSize;
  final command = machoExportsTrieCommand(
    dataOffset: dataOffset,
    dataSize: exportsTrie.length,
  );

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
    ...exportsTrie,
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

List<int> thinMachOWithObjCClassRef(String className) {
  final classNameAddress = 0x100000100;
  final classAddress = 0x100000800;
  final classRoAddress = 0x100001000;
  final classRefAddress = 0x100001800;
  final classNameData = cStringBytes([className]);
  final classData = objcClass64Bytes(classRoAddress | 0x1);
  final classRoData = objcClassRo64Bytes(classNameAddress);
  final classRefData = u64(classAddress);
  final commandsSize = 4 * (72 + 80);
  final classNameOffset = 32 + commandsSize;
  final classOffset = classNameOffset + classNameData.length;
  final classRoOffset = classOffset + classData.length;
  final classRefOffset = classRoOffset + classRoData.length;

  final textCommand = machoSegment64AddressCommand('__TEXT', [
    (
      name: '__objc_classname',
      segmentName: '__TEXT',
      address: classNameAddress,
      fileOffset: classNameOffset,
      size: classNameData.length,
    ),
  ]);
  final dataCommand = machoSegment64AddressCommand('__DATA', [
    (
      name: '__objc_data',
      segmentName: '__DATA',
      address: classAddress,
      fileOffset: classOffset,
      size: classData.length,
    ),
  ]);
  final constCommand = machoSegment64AddressCommand('__DATA_CONST', [
    (
      name: '__objc_const',
      segmentName: '__DATA_CONST',
      address: classRoAddress,
      fileOffset: classRoOffset,
      size: classRoData.length,
    ),
  ]);
  final refsCommand = machoSegment64AddressCommand('__DATA_CONST', [
    (
      name: '__objc_classrefs',
      segmentName: '__DATA_CONST',
      address: classRefAddress,
      fileOffset: classRefOffset,
      size: classRefData.length,
    ),
  ]);

  return [
    ...u32(0xfeedfacf),
    ...u32(0x0100000c),
    ...u32(0),
    ...u32(2),
    ...u32(4),
    ...u32(
      textCommand.length +
          dataCommand.length +
          constCommand.length +
          refsCommand.length,
    ),
    ...u32(0),
    ...u32(0),
    ...textCommand,
    ...dataCommand,
    ...constCommand,
    ...refsCommand,
    ...classNameData,
    ...classData,
    ...classRoData,
    ...classRefData,
  ];
}

List<int> thinMachOWithObjCProtocolRefs(
  List<String> protocolNames, {
  String sectionName = '__objc_protolist',
}) {
  final nameAddress = 0x100000100;
  final protocolAddress = 0x100001000;
  final protocolListAddress = 0x100001800;
  final namesData = cStringBytes(protocolNames);
  final nameOffsets = stringOffsets(protocolNames);
  final protocolData = [
    for (final nameOffset in nameOffsets)
      ...objcProtocol64Bytes(nameAddress + nameOffset),
  ];
  final protocolListData = [
    for (var i = 0; i < protocolNames.length; i += 1)
      ...u64(protocolAddress + i * 64),
  ];
  final commandsSize = 3 * (72 + 80);
  final nameOffset = 32 + commandsSize;
  final protocolOffset = nameOffset + namesData.length;
  final protocolListOffset = protocolOffset + protocolData.length;

  final textCommand = machoSegment64AddressCommand('__TEXT', [
    (
      name: '__objc_classname',
      segmentName: '__TEXT',
      address: nameAddress,
      fileOffset: nameOffset,
      size: namesData.length,
    ),
  ]);
  final constCommand = machoSegment64AddressCommand('__DATA_CONST', [
    (
      name: '__objc_const',
      segmentName: '__DATA_CONST',
      address: protocolAddress,
      fileOffset: protocolOffset,
      size: protocolData.length,
    ),
  ]);
  final protocolListCommand = machoSegment64AddressCommand('__DATA_CONST', [
    (
      name: sectionName,
      segmentName: '__DATA_CONST',
      address: protocolListAddress,
      fileOffset: protocolListOffset,
      size: protocolListData.length,
    ),
  ]);

  return [
    ...u32(0xfeedfacf),
    ...u32(0x0100000c),
    ...u32(0),
    ...u32(2),
    ...u32(3),
    ...u32(
      textCommand.length + constCommand.length + protocolListCommand.length,
    ),
    ...u32(0),
    ...u32(0),
    ...textCommand,
    ...constCommand,
    ...protocolListCommand,
    ...namesData,
    ...protocolData,
    ...protocolListData,
  ];
}

List<int> thinMachOWithObjCMethodList({
  required String className,
  required List<String> methodNames,
}) {
  final classNameAddress = 0x100000100;
  final methodNameAddress = 0x100000400;
  final classAddress = 0x100000800;
  final classRoAddress = 0x100001000;
  final classListAddress = 0x100001800;
  final classNameData = cStringBytes([className]);
  final methodNameData = cStringBytes(methodNames);
  final methodNameOffsets = stringOffsets(methodNames);
  final methodListAddress = classRoAddress + 40;
  final classData = objcClass64Bytes(classRoAddress);
  final classRoData = objcClassRo64Bytes(
    classNameAddress,
    baseMethodsAddress: methodListAddress,
  );
  final methodListData = objcMethodList64Bytes([
    for (final methodNameOffset in methodNameOffsets)
      methodNameAddress + methodNameOffset,
  ]);
  final classListData = u64(classAddress);
  final commandsSize = (72 + 2 * 80) + 3 * (72 + 80);
  final classNameOffset = 32 + commandsSize;
  final methodNameOffset = classNameOffset + classNameData.length;
  final classOffset = methodNameOffset + methodNameData.length;
  final classRoOffset = classOffset + classData.length;
  final methodListOffset = classRoOffset + classRoData.length;
  final classListOffset = methodListOffset + methodListData.length;

  final textCommand = machoSegment64AddressCommand('__TEXT', [
    (
      name: '__objc_classname',
      segmentName: '__TEXT',
      address: classNameAddress,
      fileOffset: classNameOffset,
      size: classNameData.length,
    ),
    (
      name: '__objc_methname',
      segmentName: '__TEXT',
      address: methodNameAddress,
      fileOffset: methodNameOffset,
      size: methodNameData.length,
    ),
  ]);
  final dataCommand = machoSegment64AddressCommand('__DATA', [
    (
      name: '__objc_data',
      segmentName: '__DATA',
      address: classAddress,
      fileOffset: classOffset,
      size: classData.length,
    ),
  ]);
  final constCommand = machoSegment64AddressCommand('__DATA_CONST', [
    (
      name: '__objc_const',
      segmentName: '__DATA_CONST',
      address: classRoAddress,
      fileOffset: classRoOffset,
      size: classRoData.length + methodListData.length,
    ),
  ]);
  final listCommand = machoSegment64AddressCommand('__DATA_CONST', [
    (
      name: '__objc_classlist',
      segmentName: '__DATA_CONST',
      address: classListAddress,
      fileOffset: classListOffset,
      size: classListData.length,
    ),
  ]);

  return [
    ...u32(0xfeedfacf),
    ...u32(0x0100000c),
    ...u32(0),
    ...u32(2),
    ...u32(4),
    ...u32(
      textCommand.length +
          dataCommand.length +
          constCommand.length +
          listCommand.length,
    ),
    ...u32(0),
    ...u32(0),
    ...textCommand,
    ...dataCommand,
    ...constCommand,
    ...listCommand,
    ...classNameData,
    ...methodNameData,
    ...classData,
    ...classRoData,
    ...methodListData,
    ...classListData,
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

List<int> machoDyldInfoCommand({
  required int bindOffset,
  required int bindSize,
}) {
  return [
    ...u32(0x80000022),
    ...u32(48),
    ...u32(0),
    ...u32(0),
    ...u32(bindOffset),
    ...u32(bindSize),
    ...u32(0),
    ...u32(0),
    ...u32(0),
    ...u32(0),
    ...u32(0),
    ...u32(0),
  ];
}

List<int> machoChainedFixupsCommand({
  required int dataOffset,
  required int dataSize,
}) {
  return [...u32(0x80000034), ...u32(16), ...u32(dataOffset), ...u32(dataSize)];
}

List<int> machoExportsTrieCommand({
  required int dataOffset,
  required int dataSize,
}) {
  return [...u32(0x80000033), ...u32(16), ...u32(dataOffset), ...u32(dataSize)];
}

List<int> dyldBindInfoBytes(List<String> symbols) {
  return [
    for (final symbol in symbols) ...[0x40, ...latin1.encode(symbol), 0, 0x90],
    0,
  ];
}

List<int> dyldExportsTrieBytes(List<String> symbols) {
  final childNodes = [
    for (var i = 0; i < symbols.length; i += 1) ...[
      ...uleb128(2),
      ...uleb128(0),
      ...uleb128(0x1000),
      0,
    ],
  ];
  final rootPrefix = [...uleb128(0), symbols.length];
  final rootEdgesWithoutOffsets = [
    for (final symbol in symbols) ...[...latin1.encode(symbol), 0],
  ];
  final rootOffsets = <List<int>>[];
  var currentChildOffset =
      rootPrefix.length + rootEdgesWithoutOffsets.length + symbols.length;
  for (var i = 0; i < symbols.length; i += 1) {
    rootOffsets.add(uleb128(currentChildOffset));
    currentChildOffset +=
        uleb128(2).length + uleb128(0).length + uleb128(0x1000).length + 1;
  }

  return [
    ...rootPrefix,
    for (var i = 0; i < symbols.length; i += 1) ...[
      ...latin1.encode(symbols[i]),
      0,
      ...rootOffsets[i],
    ],
    ...childNodes,
  ];
}

List<int> chainedFixupsPayload(List<String> symbols) {
  final symbolStrings = cStringBytes(symbols);
  final symbolOffsets = stringOffsets(symbols);
  const headerSize = 28;
  final importsOffset = headerSize;
  final symbolsOffset = importsOffset + 4 * symbols.length;

  return [
    ...u32(0),
    ...u32(0),
    ...u32(importsOffset),
    ...u32(symbolsOffset),
    ...u32(symbols.length),
    ...u32(1),
    ...u32(0),
    for (final symbolOffset in symbolOffsets) ...u32(1 | (symbolOffset << 9)),
    ...symbolStrings,
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

List<int> objcClass64Bytes(int dataAddress) {
  return [...u64(0), ...u64(0), ...u64(0), ...u64(0), ...u64(dataAddress)];
}

List<int> objcClassRo64Bytes(int nameAddress, {int baseMethodsAddress = 0}) {
  return [
    ...u32(0),
    ...u32(0),
    ...u32(0),
    ...u32(0),
    ...u64(0),
    ...u64(nameAddress),
    ...u64(baseMethodsAddress),
  ];
}

List<int> objcProtocol64Bytes(int nameAddress) {
  return [
    ...u64(0),
    ...u64(nameAddress),
    ...u64(0),
    ...u64(0),
    ...u64(0),
    ...u64(0),
    ...u64(0),
    ...u64(0),
  ];
}

List<int> objcMethodList64Bytes(List<int> methodNameAddresses) {
  return [
    ...u32(24),
    ...u32(methodNameAddresses.length),
    for (final methodNameAddress in methodNameAddresses) ...[
      ...u64(methodNameAddress),
      ...u64(0),
      ...u64(0),
    ],
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

List<int> uleb128(int value) {
  final result = <int>[];
  var remaining = value;
  do {
    var byte = remaining & 0x7f;
    remaining >>= 7;
    if (remaining != 0) byte |= 0x80;
    result.add(byte);
  } while (remaining != 0);
  return result;
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
