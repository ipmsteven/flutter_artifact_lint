import 'dart:convert';
import 'dart:io';

import 'package:flutter_artifact_lint/src/macho.dart';
import 'package:test/test.dart';

void main() {
  group('MachOParser', () {
    test('reads strong and weak linked dylib load commands', () {
      final report = const MachOParser().parse(
        thinMachO([
          machOLoadDylibCommand(
            '/System/Library/Frameworks/Contacts.framework/Contacts',
          ),
          machOLoadDylibCommand(
            '/System/Library/Frameworks/CoreLocation.framework/CoreLocation',
            weak: true,
          ),
        ]),
      );

      expect(
        report.linkedDylibs.map((dylib) => dylib.path),
        containsAll([
          '/System/Library/Frameworks/Contacts.framework/Contacts',
          '/System/Library/Frameworks/CoreLocation.framework/CoreLocation',
        ]),
      );
      expect(report.linkedDylibs.first.weak, isFalse);
      expect(report.linkedDylibs.last.weak, isTrue);
    });

    test('reads linked dylibs from fat Mach-O slices', () {
      final slice = thinMachO([
        machOLoadDylibCommand(
          '/System/Library/Frameworks/Photos.framework/Photos',
        ),
      ]);
      final report = const MachOParser().parse(fatMachO([slice]));

      expect(report.linkedDylibs.single.path, contains('Photos.framework'));
    });

    test('deduplicates linked dylibs across fat Mach-O slices', () {
      final slice = thinMachO([
        machOLoadDylibCommand(
          '/System/Library/Frameworks/CoreBluetooth.framework/CoreBluetooth',
        ),
      ]);
      final report = const MachOParser().parse(fatMachO([slice, slice]));

      expect(report.linkedDylibs, hasLength(1));
      expect(
        report.linkedDylibs.single.path,
        contains('CoreBluetooth.framework'),
      );
    });

    test('reads linked dylibs from fat64 Mach-O slices', () {
      final slice = thinMachO([
        machOLoadDylibCommand(
          '/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication',
        ),
      ]);
      final report = const MachOParser().parse(fatMachO([slice], fat64: true));

      expect(
        report.linkedDylibs.single.path,
        contains('LocalAuthentication.framework'),
      );
    });

    test('reads architecture from a thin Mach-O header', () {
      final report = const MachOParser().parse(thinMachO([]));

      expect(report.architectures, hasLength(1));
      expect(report.architectures.single.name, 'arm64');
    });

    test('distinguishes arm64e architecture subtype', () {
      final report = const MachOParser().parse(thinMachO([], cpuSubtype: 2));

      expect(report.architectures.single.name, 'arm64e');
    });

    test('reads and deduplicates architectures from fat Mach-O slices', () {
      final arm64Slice = thinMachO([], cpuType: 0x0100000c);
      final x8664Slice = thinMachO([], cpuType: 0x01000007);
      final report = const MachOParser().parse(
        fatMachO([arm64Slice, x8664Slice, arm64Slice]),
      );

      expect(
        report.architectures.map((architecture) => architecture.name),
        containsAll(['arm64', 'x86_64']),
      );
      expect(report.architectures, hasLength(2));
    });

    test('does not read commands beyond sizeofcmds', () {
      final report = const MachOParser().parse([
        ...machOHeader64(ncmds: 1, sizeofcmds: 0),
        ...machOLoadDylibCommand(
          '/System/Library/Frameworks/Contacts.framework/Contacts',
        ),
      ]);

      expect(report.linkedDylibs, isEmpty);
    });

    test('reads reexport upward and lazy linked dylib commands', () {
      final report = const MachOParser().parse(
        thinMachO([
          machOLoadDylibCommand(
            '/System/Library/Frameworks/Contacts.framework/Contacts',
            command: 0x8000001f,
          ),
          machOLoadDylibCommand(
            '/System/Library/Frameworks/Photos.framework/Photos',
            command: 0x80000023,
          ),
          machOLoadDylibCommand(
            '/System/Library/Frameworks/UserNotifications.framework/UserNotifications',
            command: 0x20,
          ),
        ]),
      );

      expect(
        report.linkedDylibs.map((dylib) => dylib.path),
        containsAll([
          contains('Contacts.framework'),
          contains('Photos.framework'),
          contains('UserNotifications.framework'),
        ]),
      );
    });

    test('reads LC_BUILD_VERSION metadata', () {
      final report = const MachOParser().parse(
        thinMachO([
          machoBuildVersionCommand(
            platform: 2,
            minimumOsVersion: 0x000c0000,
            sdkVersion: 0x00110000,
          ),
        ]),
      );

      expect(report.buildVersions, hasLength(1));
      expect(report.buildVersions.single.platformName, 'iOS');
      expect(report.buildVersions.single.minimumOsVersion, '12.0.0');
      expect(report.buildVersions.single.sdkVersion, '17.0.0');
    });

    test('reads LC_BUILD_VERSION tool versions', () {
      final report = const MachOParser().parse(
        thinMachO([
          machoBuildVersionCommand(
            platform: 2,
            minimumOsVersion: 0x000c0000,
            sdkVersion: 0x00110000,
            tools: [
              (tool: 1, version: 0x000f0000),
              (tool: 2, version: 0x00050900),
            ],
          ),
        ]),
      );

      expect(report.buildVersions.single.tools, hasLength(2));
      expect(report.buildVersions.single.tools.first.toolName, 'clang');
      expect(report.buildVersions.single.tools.first.version, '15.0.0');
      expect(report.buildVersions.single.tools.last.toolName, 'swift');
      expect(report.buildVersions.single.tools.last.version, '5.9.0');
    });

    test('reads legacy LC_VERSION_MIN_IPHONEOS metadata', () {
      final report = const MachOParser().parse(
        thinMachO([
          machoVersionMinCommand(
            command: 0x25,
            minimumOsVersion: 0x000b0200,
            sdkVersion: 0x000e0400,
          ),
        ]),
      );

      expect(report.buildVersions, hasLength(1));
      expect(report.buildVersions.single.platformName, 'iOS');
      expect(report.buildVersions.single.minimumOsVersion, '11.2.0');
      expect(report.buildVersions.single.sdkVersion, '14.4.0');
    });

    test('deduplicates LC_BUILD_VERSION metadata across fat Mach-O slices', () {
      final slice = thinMachO([
        machoBuildVersionCommand(
          platform: 2,
          minimumOsVersion: 0x000d0100,
          sdkVersion: 0x00120000,
        ),
      ]);
      final report = const MachOParser().parse(fatMachO([slice, slice]));

      expect(report.buildVersions, hasLength(1));
      expect(report.buildVersions.single.minimumOsVersion, '13.1.0');
      expect(report.buildVersions.single.sdkVersion, '18.0.0');
    });

    test('reads diagnostic Mach-O metadata load commands', () {
      final report = const MachOParser().parse(
        thinMachO([
          machoRpathCommand('@executable_path/Frameworks'),
          machoDylibIdCommand('@rpath/Runner.framework/Runner'),
          machoUuidCommand([
            0x00,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            0x66,
            0x77,
            0x88,
            0x99,
            0xaa,
            0xbb,
            0xcc,
            0xdd,
            0xee,
            0xff,
          ]),
          machoSourceVersionCommand(sourceVersion(1, 2, 3, 4, 5)),
          machoCodeSignatureCommand(dataOffset: 4096, dataSize: 512),
        ]),
      );

      expect(report.rpaths.single.path, '@executable_path/Frameworks');
      expect(report.dylibIds.single.path, '@rpath/Runner.framework/Runner');
      expect(report.uuids.single.value, '00112233-4455-6677-8899-aabbccddeeff');
      expect(report.sourceVersions.single.version, '1.2.3.4.5');
      expect(report.codeSignatures.single.dataOffset, 4096);
      expect(report.codeSignatures.single.dataSize, 512);
    });

    test('reads LC_ENCRYPTION_INFO metadata', () {
      final report = const MachOParser().parse(
        thinMachO([
          machoEncryptionInfoCommand(
            cryptOffset: 8192,
            cryptSize: 4096,
            cryptId: 1,
          ),
        ]),
      );

      expect(report.encryptionInfos, hasLength(1));
      expect(report.encryptionInfos.single.cryptOffset, 8192);
      expect(report.encryptionInfos.single.cryptSize, 4096);
      expect(report.encryptionInfos.single.cryptId, 1);
      expect(report.encryptionInfos.single.encrypted, isTrue);
    });

    test('reads LC_ENCRYPTION_INFO_64 metadata', () {
      final report = const MachOParser().parse(
        thinMachO([
          machoEncryptionInfoCommand(
            cryptOffset: 12288,
            cryptSize: 0,
            cryptId: 0,
            command: 0x2c,
          ),
        ]),
      );

      expect(report.encryptionInfos, hasLength(1));
      expect(report.encryptionInfos.single.cryptOffset, 12288);
      expect(report.encryptionInfos.single.cryptSize, 0);
      expect(report.encryptionInfos.single.cryptId, 0);
      expect(report.encryptionInfos.single.encrypted, isFalse);
    });

    test('reads LC_MAIN entry point metadata', () {
      final report = const MachOParser().parse(
        thinMachO([machoMainCommand(entryOffset: 0x1234, stackSize: 0x4000)]),
      );

      expect(report.entryPoints, hasLength(1));
      expect(report.entryPoints.single.entryOffset, 0x1234);
      expect(report.entryPoints.single.stackSize, 0x4000);
    });

    test('reads LC_SEGMENT_64 segment and section names', () {
      final report = const MachOParser().parse(
        thinMachO([
          machoSegment64Command('__TEXT', [
            (name: '__text', segmentName: '__TEXT'),
            (name: '__objc_methname', segmentName: '__TEXT'),
          ]),
        ]),
      );

      expect(report.segments.single.name, '__TEXT');
      expect(
        report.segments.single.sections.map((section) => section.name),
        containsAll(['__text', '__objc_methname']),
      );
      expect(
        report.segments.single.sections.map((section) => section.displayName),
        containsAll(['__TEXT.__text', '__TEXT.__objc_methname']),
      );
    });

    test('reads LC_SYMTAB metadata and symbols from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithSymbolTable([
          '_UIApplicationOpenSettingsURLString',
          '_swift_getFunctionReplacement',
        ]),
      );

      expect(report.symbolTables.single.symbolCount, 2);
      expect(
        report.symbols.map((symbol) => symbol.name),
        containsAll([
          '_UIApplicationOpenSettingsURLString',
          '_swift_getFunctionReplacement',
        ]),
      );
    });

    test('reads LC_SYMTAB symbols from the file-backed parser', () async {
      final root = await Directory.systemTemp.createTemp('fal_macho_');
      addTearDown(() => root.deleteSync(recursive: true));

      final file = File('${root.path}/Runner')
        ..writeAsBytesSync(
          thinMachOWithSymbolTable([
            r'_OBJC_CLASS_$_RunnerViewController',
            '_OBJC_SELECTOR_REFERENCES_',
          ], paddingBeforeSymbolTable: 4096),
        );

      final report = const MachOParser().parseFile(file);

      expect(report.symbolTables.single.symbolCount, 2);
      expect(
        report.symbols.map((symbol) => symbol.name),
        containsAll([
          r'_OBJC_CLASS_$_RunnerViewController',
          '_OBJC_SELECTOR_REFERENCES_',
        ]),
      );
    });

    test('reads LC_DYSYMTAB metadata', () {
      final report = const MachOParser().parse(
        thinMachO([
          machoDynamicSymtabCommand(
            localSymbolIndex: 1,
            localSymbolCount: 2,
            externalSymbolIndex: 3,
            externalSymbolCount: 4,
            undefinedSymbolIndex: 7,
            undefinedSymbolCount: 8,
            indirectSymbolOffset: 4096,
            indirectSymbolCount: 16,
          ),
        ]),
      );

      final table = report.dynamicSymbolTables.single;
      expect(table.localSymbolIndex, 1);
      expect(table.localSymbolCount, 2);
      expect(table.externalSymbolIndex, 3);
      expect(table.externalSymbolCount, 4);
      expect(table.undefinedSymbolIndex, 7);
      expect(table.undefinedSymbolCount, 8);
      expect(table.indirectSymbolOffset, 4096);
      expect(table.indirectSymbolCount, 16);
    });

    test('reads LC_DYLD_INFO bind symbols from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithDyldBindSymbols([
          r'_OBJC_CLASS_$_CLLocationManager',
          '_UIApplicationOpenSettingsURLString',
        ]),
      );

      expect(
        report.dyldBindSymbols.map((symbol) => symbol.name),
        containsAll([
          r'_OBJC_CLASS_$_CLLocationManager',
          '_UIApplicationOpenSettingsURLString',
        ]),
      );
    });

    test(
      'reads LC_DYLD_INFO bind symbols from the file-backed parser',
      () async {
        final root = await Directory.systemTemp.createTemp('fal_macho_');
        addTearDown(() => root.deleteSync(recursive: true));

        final file = File('${root.path}/Runner')
          ..writeAsBytesSync(
            thinMachOWithDyldBindSymbols([
              r'_OBJC_CLASS_$_UNUserNotificationCenter',
            ], paddingBeforeBindInfo: 4096),
          );

        final report = const MachOParser().parseFile(file);

        expect(
          report.dyldBindSymbols.single.name,
          r'_OBJC_CLASS_$_UNUserNotificationCenter',
        );
      },
    );

    test('reads LC_DYLD_CHAINED_FIXUPS import symbols from bytes', () {
      for (final importFormat in [1, 2, 3]) {
        final report = const MachOParser().parse(
          thinMachOWithChainedFixupImports([
            r'_OBJC_CLASS_$_CLLocationManager',
          ], importFormat: importFormat),
        );

        expect(
          report.dyldBindSymbols.map((symbol) => symbol.name),
          contains(r'_OBJC_CLASS_$_CLLocationManager'),
          reason: 'import format $importFormat',
        );
      }
    });

    test('reads LC_DYLD_CHAINED_FIXUPS starts metadata from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithChainedFixupImports([
          r'_OBJC_CLASS_$_CLLocationManager',
        ], includeStartsMetadata: true),
      );

      final chainedFixups = report.chainedFixups.single;
      expect(chainedFixups.fixupsVersion, 0);
      expect(chainedFixups.importsCount, 1);
      expect(chainedFixups.importsFormat, 1);
      expect(chainedFixups.symbolsFormat, 0);
      expect(chainedFixups.segments, hasLength(1));
      expect(chainedFixups.segments.single.pageSize, 0x4000);
      expect(chainedFixups.segments.single.pointerFormat, 9);
      expect(chainedFixups.segments.single.segmentOffset, 0x8000);
      expect(chainedFixups.segments.single.pageStarts, [0x18, 0xffff]);
    });

    test(
      'reads LC_DYLD_CHAINED_FIXUPS starts metadata from the file-backed parser',
      () async {
        final root = await Directory.systemTemp.createTemp('fal_macho_');
        addTearDown(() => root.deleteSync(recursive: true));

        final file = File('${root.path}/Runner')
          ..writeAsBytesSync(
            thinMachOWithChainedFixupImports(
              [r'_OBJC_CLASS_$_UNUserNotificationCenter'],
              includeStartsMetadata: true,
              paddingBeforeChainedFixups: 4096,
            ),
          );

        final report = const MachOParser().parseFile(file);

        expect(report.chainedFixups.single.segments, hasLength(1));
        expect(report.chainedFixups.single.segments.single.pointerFormat, 9);
        expect(report.chainedFixups.single.segments.single.pageStarts, [
          0x18,
          0xffff,
        ]);
      },
    );

    test(
      'reads LC_DYLD_CHAINED_FIXUPS starts metadata without imports from the file-backed parser',
      () async {
        final root = await Directory.systemTemp.createTemp('fal_macho_');
        addTearDown(() => root.deleteSync(recursive: true));

        final file = File('${root.path}/Runner')
          ..writeAsBytesSync(
            thinMachOWithChainedFixupImports(
              const [],
              includeStartsMetadata: true,
              paddingBeforeChainedFixups: 4096,
            ),
          );

        final report = const MachOParser().parseFile(file);

        expect(report.chainedFixups.single.importsCount, 0);
        expect(report.chainedFixups.single.segments, hasLength(1));
      },
    );

    test('reads LC_FUNCTION_STARTS offsets from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithFunctionStarts([0x100, 0x120, 0x1a0]),
      );

      expect(report.functionStarts, hasLength(1));
      expect(report.functionStarts.single.dataSize, greaterThan(0));
      expect(report.functionStarts.single.offsets, [0x100, 0x120, 0x1a0]);
    });

    test('reads LC_FUNCTION_STARTS offsets from the file-backed parser', () {
      final root = Directory.systemTemp.createTempSync('fal_macho_');
      addTearDown(() => root.deleteSync(recursive: true));

      final file = File('${root.path}/Runner')
        ..writeAsBytesSync(thinMachOWithFunctionStarts([0x200, 0x240, 0x300]));

      final report = const MachOParser().parseFile(file);

      expect(report.functionStarts.single.offsets, [0x200, 0x240, 0x300]);
    });

    test('reads LC_DATA_IN_CODE entries from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithDataInCode([
          (offset: 0x20, length: 8, kind: 1),
          (offset: 0x80, length: 16, kind: 4),
        ]),
      );

      expect(report.dataInCode, hasLength(1));
      expect(report.dataInCode.single.entries, hasLength(2));
      expect(report.dataInCode.single.entries.first.offset, 0x20);
      expect(report.dataInCode.single.entries.first.length, 8);
      expect(report.dataInCode.single.entries.first.kindName, 'data');
      expect(report.dataInCode.single.entries.last.kindName, 'jump table 32');
    });

    test('reads LC_LINKER_OPTION strings from bytes', () {
      final report = const MachOParser().parse(
        thinMachO([
          machoLinkerOptionCommand(['-framework', 'Contacts']),
        ]),
      );

      expect(report.linkerOptions.single.values, ['-framework', 'Contacts']);
    });

    test('reads dyld string load commands from bytes', () {
      final report = const MachOParser().parse(
        thinMachO([
          machoPathCommand(0x0e, '/usr/lib/dyld'),
          machoPathCommand(
            0x27,
            'DYLD_INSERT_LIBRARIES=@executable_path/Inject.dylib',
          ),
        ]),
      );

      expect(report.dylinkers.single.path, '/usr/lib/dyld');
      expect(
        report.dyldEnvironments.single.value,
        'DYLD_INSERT_LIBRARIES=@executable_path/Inject.dylib',
      );
    });

    test('reads LC_DATA_IN_CODE entries from the file-backed parser', () {
      final root = Directory.systemTemp.createTempSync('fal_macho_');
      addTearDown(() => root.deleteSync(recursive: true));

      final file = File('${root.path}/Runner')
        ..writeAsBytesSync(
          thinMachOWithDataInCode([
            (offset: 0x40, length: 4, kind: 2),
          ], paddingBeforeDataInCode: 4096),
        );

      final report = const MachOParser().parseFile(file);

      expect(report.dataInCode.single.entries.single.offset, 0x40);
      expect(report.dataInCode.single.entries.single.kindName, 'jump table 8');
    });

    test('reads LC_LINKER_OPTION strings from the file-backed parser', () {
      final root = Directory.systemTemp.createTempSync('fal_macho_');
      addTearDown(() => root.deleteSync(recursive: true));

      final file = File('${root.path}/Runner')
        ..writeAsBytesSync(
          thinMachO([
            machoLinkerOptionCommand(['-framework', 'UserNotifications']),
          ]),
        );

      final report = const MachOParser().parseFile(file);

      expect(report.linkerOptions.single.values, [
        '-framework',
        'UserNotifications',
      ]);
    });

    test('reads dyld string load commands from the file-backed parser', () {
      final root = Directory.systemTemp.createTempSync('fal_macho_');
      addTearDown(() => root.deleteSync(recursive: true));

      final file = File('${root.path}/Runner')
        ..writeAsBytesSync(
          thinMachO([
            machoPathCommand(0x0e, '/usr/lib/dyld'),
            machoPathCommand(0x27, 'DYLD_PRINT_STATISTICS=1'),
          ]),
        );

      final report = const MachOParser().parseFile(file);

      expect(report.dylinkers.single.path, '/usr/lib/dyld');
      expect(report.dyldEnvironments.single.value, 'DYLD_PRINT_STATISTICS=1');
    });

    test(
      'reads compressed LC_DYLD_CHAINED_FIXUPS import symbols from bytes',
      () {
        final report = const MachOParser().parse(
          thinMachOWithChainedFixupImports([
            r'_OBJC_CLASS_$_UNUserNotificationCenter',
          ], symbolsFormat: 1),
        );

        expect(
          report.dyldBindSymbols.map((symbol) => symbol.name),
          contains(r'_OBJC_CLASS_$_UNUserNotificationCenter'),
        );
      },
    );

    test('ignores malformed compressed LC_DYLD_CHAINED_FIXUPS symbols', () {
      final report = const MachOParser().parse(
        thinMachOWithChainedFixupImports(
          [r'_OBJC_CLASS_$_UNUserNotificationCenter'],
          corruptCompressedSymbols: true,
          symbolsFormat: 1,
        ),
      );

      expect(report.dyldBindSymbols, isEmpty);
    });

    test(
      'reads LC_DYLD_CHAINED_FIXUPS import symbols from the file-backed parser',
      () async {
        final root = await Directory.systemTemp.createTemp('fal_macho_');
        addTearDown(() => root.deleteSync(recursive: true));

        final file = File('${root.path}/Runner')
          ..writeAsBytesSync(
            thinMachOWithChainedFixupImports(
              [r'_OBJC_CLASS_$_UNUserNotificationCenter'],
              importFormat: 3,
              paddingBeforeChainedFixups: 4096,
            ),
          );

        final report = const MachOParser().parseFile(file);

        expect(
          report.dyldBindSymbols.single.name,
          r'_OBJC_CLASS_$_UNUserNotificationCenter',
        );
      },
    );

    test('reads LC_DYLD_EXPORTS_TRIE symbols from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithDyldExportsTrie([
          r'_OBJC_CLASS_$_RunnerViewController',
          '_UIApplicationOpenSettingsURLString',
        ]),
      );

      expect(
        report.dyldExportSymbols.map((symbol) => symbol.name),
        containsAll([
          r'_OBJC_CLASS_$_RunnerViewController',
          '_UIApplicationOpenSettingsURLString',
        ]),
      );
    });

    test('reads LC_DYLD_INFO export trie symbols from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithDyldInfoExportsTrie([
          r'_OBJC_CLASS_$_AppDelegate',
          '_UIApplicationOpenSettingsURLString',
        ]),
      );

      expect(
        report.dyldExportSymbols.map((symbol) => symbol.name),
        containsAll([
          r'_OBJC_CLASS_$_AppDelegate',
          '_UIApplicationOpenSettingsURLString',
        ]),
      );
    });

    test(
      'reads LC_DYLD_EXPORTS_TRIE symbols from the file-backed parser',
      () async {
        final root = await Directory.systemTemp.createTemp('fal_macho_');
        addTearDown(() => root.deleteSync(recursive: true));

        final file = File('${root.path}/Runner')
          ..writeAsBytesSync(
            thinMachOWithDyldExportsTrie([
              '_FlutterAppDelegate',
            ], paddingBeforeExportsTrie: 4096),
          );

        final report = const MachOParser().parseFile(file);

        expect(report.dyldExportSymbols.single.name, '_FlutterAppDelegate');
      },
    );

    test('reads C strings from Objective-C method sections', () {
      final report = const MachOParser().parse(
        thinMachOWithCStringSection(
          segmentName: '__TEXT',
          sectionName: '__objc_methname',
          values: ['requestWhenInUseAuthorization', 'cameraCaptureDidStart:'],
        ),
      );

      expect(
        report.sectionStrings.map((sectionString) => sectionString.value),
        containsAll([
          'requestWhenInUseAuthorization',
          'cameraCaptureDidStart:',
        ]),
      );
      expect(
        report.sectionStrings.map((sectionString) => sectionString.sectionName),
        everyElement('__TEXT.__objc_methname'),
      );
    });

    test('reads strings from Swift metadata sections', () {
      final reflectionReport = const MachOParser().parse(
        thinMachOWithCStringSection(
          segmentName: '__TEXT',
          sectionName: '__swift5_reflstr',
          values: ['cameraUsageDescription', 'locationWhenInUse'],
        ),
      );
      final typeRefReport = const MachOParser().parse(
        thinMachOWithCStringSection(
          segmentName: '__TEXT',
          sectionName: '__swift5_typeref',
          values: [r'$s6Fields15PermissionStateV', 'So8NSObjectC'],
        ),
      );

      expect(
        reflectionReport.sectionStrings.map(
          (sectionString) => sectionString.value,
        ),
        containsAll(['cameraUsageDescription', 'locationWhenInUse']),
      );
      expect(
        reflectionReport.sectionStrings.map(
          (sectionString) => sectionString.sectionName,
        ),
        everyElement('__TEXT.__swift5_reflstr'),
      );
      expect(
        typeRefReport.sectionStrings.map(
          (sectionString) => sectionString.value,
        ),
        containsAll([r'$s6Fields15PermissionStateV', 'So8NSObjectC']),
      );
    });

    test('resolves Swift type descriptors from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithSwiftTypeDescriptors(['PermissionState', 'CameraPurpose']),
      );

      expect(
        report.swiftTypes.map((swiftType) => swiftType.name),
        containsAll(['PermissionState', 'CameraPurpose']),
      );
      expect(
        report.swiftTypes.map((swiftType) => swiftType.sourceSection),
        everyElement('__TEXT.__swift5_types'),
      );
    });

    test('resolves Swift protocol conformances from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithSwiftProtocolConformances([
          (typeName: 'PermissionState', protocolName: 'PermissionProtocol'),
          (typeName: 'CameraPurpose', protocolName: 'CameraPurposeProviding'),
        ]),
      );

      expect(
        report.swiftProtocolConformances.map(
          (conformance) => conformance.typeName,
        ),
        containsAll(['PermissionState', 'CameraPurpose']),
      );
      expect(
        report.swiftProtocolConformances.map(
          (conformance) => conformance.protocolName,
        ),
        containsAll(['PermissionProtocol', 'CameraPurposeProviding']),
      );
      expect(
        report.swiftProtocolConformances.map(
          (conformance) => conformance.sourceSection,
        ),
        everyElement('__TEXT.__swift5_proto'),
      );
    });

    test('resolves Swift protocol descriptors from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithSwiftProtocolDescriptors([
          'PermissionProtocol',
          'CameraPurposeProviding',
        ]),
      );

      expect(
        report.swiftProtocols.map((protocol) => protocol.name),
        containsAll(['PermissionProtocol', 'CameraPurposeProviding']),
      );
      expect(
        report.swiftProtocols.map((protocol) => protocol.sourceSection),
        everyElement('__TEXT.__swift5_protos'),
      );
    });

    test('resolves Swift field descriptors from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithSwiftFieldDescriptors([
          (
            ownerTypeName: 'PermissionState',
            fields: [
              (name: 'authorized', typeName: 'Bool'),
              (name: 'cameraPurpose', typeName: 'String'),
            ],
          ),
          (
            ownerTypeName: 'CameraPurpose',
            fields: [(name: 'label', typeName: 'String')],
          ),
        ]),
      );

      expect(
        report.swiftFields.map((field) => field.ownerTypeName),
        containsAll(['PermissionState', 'CameraPurpose']),
      );
      expect(
        report.swiftFields.map((field) => field.name),
        containsAll(['authorized', 'cameraPurpose', 'label']),
      );
      expect(
        report.swiftFields.map((field) => field.fieldTypeName),
        containsAll(['Bool', 'String']),
      );
      expect(
        report.swiftFields.map((field) => field.sourceSection),
        everyElement('__TEXT.__swift5_fieldmd'),
      );
    });

    test(
      'resolves Swift field descriptor superclass references from bytes',
      () {
        final report = const MachOParser().parse(
          thinMachOWithSwiftFieldDescriptors([
            (
              ownerTypeName: 'NotificationHandler',
              fields: [(name: 'center', typeName: 'UNUserNotificationCenter')],
            ),
          ], superclassTypeName: 'UNNotificationServiceExtension'),
        );

        expect(
          report.swiftFields.single.superclassTypeName,
          'UNNotificationServiceExtension',
        );
      },
    );

    test('reads C strings from the file-backed parser', () async {
      final root = await Directory.systemTemp.createTemp('fal_macho_');
      addTearDown(() => root.deleteSync(recursive: true));

      final file = File('${root.path}/Runner')
        ..writeAsBytesSync(
          thinMachOWithCStringSection(
            segmentName: '__TEXT',
            sectionName: '__cstring',
            values: ['UNUserNotificationCenter', 'FirebaseMessaging'],
            paddingBeforeStrings: 4096,
          ),
        );

      final report = const MachOParser().parseFile(file);

      expect(
        report.sectionStrings.map((sectionString) => sectionString.value),
        containsAll(['UNUserNotificationCenter', 'FirebaseMessaging']),
      );
    });

    test('resolves Objective-C selector references from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithObjCSelectorRefs([
          'requestWhenInUseAuthorization',
          'setDelegate:',
        ]),
      );

      expect(
        report.objcSelectors.map((selector) => selector.name),
        containsAll(['requestWhenInUseAuthorization', 'setDelegate:']),
      );
      expect(
        report.objcSelectors.map((selector) => selector.sourceSection),
        everyElement('__DATA_CONST.__objc_selrefs'),
      );
    });

    test('resolves chained Objective-C selector pointers from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithObjCSelectorRefs([
          'requestWhenInUseAuthorization',
          'setDelegate:',
        ], chainedPointers: true),
      );

      expect(
        report.objcSelectors.map((selector) => selector.name),
        containsAll(['requestWhenInUseAuthorization', 'setDelegate:']),
      );
    });

    test(
      'resolves authenticated chained Objective-C selector pointers from bytes',
      () {
        final report = const MachOParser().parse(
          thinMachOWithObjCSelectorRefs([
            'requestWhenInUseAuthorization',
            'setDelegate:',
          ], authenticatedChainedPointers: true),
        );

        expect(
          report.objcSelectors.map((selector) => selector.name),
          containsAll(['requestWhenInUseAuthorization', 'setDelegate:']),
        );
      },
    );

    test(
      'does not resolve authenticated chained bind pointers as Objective-C selector pointers',
      () {
        final report = const MachOParser().parse(
          thinMachOWithObjCSelectorRefs([
            'requestWhenInUseAuthorization',
          ], authenticatedChainedBindPointers: true),
        );

        expect(report.objcSelectors, isEmpty);
      },
    );

    test(
      'resolves Objective-C selector references from the file-backed parser',
      () async {
        final root = await Directory.systemTemp.createTemp('fal_macho_');
        addTearDown(() => root.deleteSync(recursive: true));

        final file = File('${root.path}/Runner')
          ..writeAsBytesSync(
            thinMachOWithObjCSelectorRefs([
              'requestAuthorizationWithOptions:completionHandler:',
              'authorizationStatus',
            ], paddingBeforeData: 4096),
          );

        final report = const MachOParser().parseFile(file);

        expect(
          report.objcSelectors.map((selector) => selector.name),
          containsAll([
            'requestAuthorizationWithOptions:completionHandler:',
            'authorizationStatus',
          ]),
        );
      },
    );

    test(
      'resolves authenticated chained Objective-C selector pointers from the file-backed parser',
      () async {
        final root = await Directory.systemTemp.createTemp('fal_macho_');
        addTearDown(() => root.deleteSync(recursive: true));

        final file = File('${root.path}/Runner')
          ..writeAsBytesSync(
            thinMachOWithObjCSelectorRefs(
              [
                'requestAuthorizationWithOptions:completionHandler:',
                'authorizationStatus',
              ],
              paddingBeforeData: 4096,
              authenticatedChainedPointers: true,
            ),
          );

        final report = const MachOParser().parseFile(file);

        expect(
          report.objcSelectors.map((selector) => selector.name),
          containsAll([
            'requestAuthorizationWithOptions:completionHandler:',
            'authorizationStatus',
          ]),
        );
      },
    );

    test('resolves Objective-C class references from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithObjCClassRef('CLLocationManager'),
      );

      expect(report.objcClasses.single.name, 'CLLocationManager');
      expect(
        report.objcClasses.single.sourceSection,
        '__DATA_CONST.__objc_classrefs',
      );
    });

    test('resolves Objective-C superclass names from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithObjCClassRef(
          'RunnerNotificationExtension',
          superclassName: 'UNNotificationServiceExtension',
        ),
      );

      expect(report.objcClasses.single.name, 'RunnerNotificationExtension');
      expect(
        report.objcClasses.single.superclassName,
        'UNNotificationServiceExtension',
      );
    });

    test(
      'resolves Objective-C class references from the file-backed parser',
      () async {
        final root = await Directory.systemTemp.createTemp('fal_macho_');
        addTearDown(() => root.deleteSync(recursive: true));

        final file = File('${root.path}/Runner')
          ..writeAsBytesSync(
            thinMachOWithObjCClassRef(
              'UNUserNotificationCenter',
              paddingBeforeData: 4096,
            ),
          );

        final report = const MachOParser().parseFile(file);

        expect(report.objcClasses.single.name, 'UNUserNotificationCenter');
        expect(
          report.objcClasses.single.sourceSection,
          '__DATA_CONST.__objc_classrefs',
        );
      },
    );

    test(
      'resolves Objective-C superclass names from the file-backed parser',
      () async {
        final root = await Directory.systemTemp.createTemp('fal_macho_');
        addTearDown(() => root.deleteSync(recursive: true));

        final file = File('${root.path}/Runner')
          ..writeAsBytesSync(
            thinMachOWithObjCClassRef(
              'RunnerNotificationExtension',
              superclassName: 'UNNotificationServiceExtension',
              paddingBeforeData: 4096,
            ),
          );

        final report = const MachOParser().parseFile(file);

        expect(
          report.objcClasses.single.superclassName,
          'UNNotificationServiceExtension',
        );
      },
    );

    test('resolves Objective-C protocol references from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithObjCProtocolRefs([
          'FlutterPlugin',
          'UIApplicationDelegate',
        ]),
      );

      expect(
        report.objcProtocols.map((protocol) => protocol.name),
        containsAll(['FlutterPlugin', 'UIApplicationDelegate']),
      );
      expect(
        report.objcProtocols.map((protocol) => protocol.sourceSection),
        everyElement('__DATA_CONST.__objc_protolist'),
      );
    });

    test('resolves Objective-C inherited protocol references from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithObjCProtocolInheritance(
          protocolName: 'FlutterPlugin',
          inheritedProtocolName: 'UIApplicationDelegate',
        ),
      );

      expect(
        report.objcProtocols.map((protocol) => protocol.name),
        containsAll(['FlutterPlugin', 'UIApplicationDelegate']),
      );
      expect(
        report.objcProtocols
            .singleWhere((protocol) => protocol.name == 'UIApplicationDelegate')
            .sourceSection,
        '__DATA_CONST.__objc_const',
      );
    });

    test(
      'resolves Objective-C protocol references from the file-backed parser',
      () async {
        final root = await Directory.systemTemp.createTemp('fal_macho_');
        addTearDown(() => root.deleteSync(recursive: true));

        final file = File('${root.path}/Runner')
          ..writeAsBytesSync(
            thinMachOWithObjCProtocolRefs(
              ['FlutterStreamHandler'],
              paddingBeforeData: 4096,
              sectionName: '__objc_protorefs',
            ),
          );

        final report = const MachOParser().parseFile(file);

        expect(report.objcProtocols.single.name, 'FlutterStreamHandler');
        expect(
          report.objcProtocols.single.sourceSection,
          '__DATA_CONST.__objc_protorefs',
        );
      },
    );

    test(
      'resolves Objective-C class protocol conformance lists from bytes',
      () {
        final report = const MachOParser().parse(
          thinMachOWithObjCClassProtocolList(
            className: 'RunnerAppDelegate',
            protocolNames: ['FlutterPlugin'],
          ),
        );

        expect(report.objcProtocols.single.name, 'FlutterPlugin');
        expect(
          report.objcProtocols.single.sourceSection,
          '__DATA_CONST.__objc_const',
        );
      },
    );

    test(
      'resolves Objective-C category protocol conformance lists from bytes',
      () {
        final report = const MachOParser().parse(
          thinMachOWithObjCCategoryProtocolList(
            className: 'RunnerAppDelegate',
            categoryName: 'Notifications',
            protocolNames: ['UNUserNotificationCenterDelegate'],
          ),
        );

        expect(
          report.objcProtocols.single.name,
          'UNUserNotificationCenterDelegate',
        );
        expect(
          report.objcProtocols.single.sourceSection,
          '__DATA_CONST.__objc_const',
        );
      },
    );

    test('resolves Objective-C protocol method lists from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithObjCProtocolMethodList(
          protocolName: 'FlutterPlugin',
          methodNames: ['registrar', 'registerWithRegistrar:'],
        ),
      );

      expect(
        report.objcMethods.map((method) => method.name),
        containsAll(['registrar', 'registerWithRegistrar:']),
      );
      expect(
        report.objcMethods.map((method) => method.className),
        everyElement('FlutterPlugin'),
      );
      expect(
        report.objcMethods.map((method) => method.sourceSection),
        everyElement('__DATA_CONST.__objc_const'),
      );
    });

    test('resolves inherited Objective-C protocol method lists from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithObjCInheritedProtocolMethodList(
          protocolName: 'FlutterPlugin',
          inheritedProtocolName: 'UIApplicationDelegate',
          inheritedMethodNames: ['application:didFinishLaunchingWithOptions:'],
        ),
      );

      expect(report.objcMethods.map((method) => method.name), [
        'application:didFinishLaunchingWithOptions:',
      ]);
      expect(report.objcMethods.single.className, 'UIApplicationDelegate');
      expect(
        report.objcMethods.single.sourceSection,
        '__DATA_CONST.__objc_const',
      );
    });

    test('resolves Objective-C method lists from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithObjCMethodList(
          className: 'RunnerViewController',
          methodNames: ['viewDidLoad', 'requestWhenInUseAuthorization'],
        ),
      );

      expect(
        report.objcMethods.map((method) => method.name),
        containsAll(['viewDidLoad', 'requestWhenInUseAuthorization']),
      );
      expect(
        report.objcMethods.map((method) => method.className),
        everyElement('RunnerViewController'),
      );
      expect(
        report.objcMethods.map((method) => method.sourceSection),
        everyElement('__DATA_CONST.__objc_const'),
      );
    });

    test('resolves Objective-C method lists from the file-backed parser', () async {
      final root = await Directory.systemTemp.createTemp('fal_macho_');
      addTearDown(() => root.deleteSync(recursive: true));

      final file = File('${root.path}/Runner')
        ..writeAsBytesSync(
          thinMachOWithObjCMethodList(
            className: 'NotificationDelegate',
            methodNames: [
              'userNotificationCenter:didReceiveNotificationResponse:withCompletionHandler:',
            ],
            paddingBeforeData: 4096,
          ),
        );

      final report = const MachOParser().parseFile(file);

      expect(
        report.objcMethods.single.name,
        'userNotificationCenter:didReceiveNotificationResponse:withCompletionHandler:',
      );
      expect(report.objcMethods.single.className, 'NotificationDelegate');
    });

    test('resolves Objective-C relative method list lists from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithObjCMethodList(
          className: 'RelativeDelegate',
          methodNames: ['application:openURL:options:'],
          relativeBaseMethods: true,
        ),
      );

      expect(report.objcMethods.single.name, 'application:openURL:options:');
      expect(report.objcMethods.single.className, 'RelativeDelegate');
    });

    test(
      'resolves Objective-C relative method list lists from the file-backed parser',
      () async {
        final root = await Directory.systemTemp.createTemp('fal_macho_');
        addTearDown(() => root.deleteSync(recursive: true));

        final file = File('${root.path}/Runner')
          ..writeAsBytesSync(
            thinMachOWithObjCMethodList(
              className: 'RelativeNotificationDelegate',
              methodNames: [
                'userNotificationCenter:openSettingsForNotification:',
              ],
              paddingBeforeData: 4096,
              relativeBaseMethods: true,
            ),
          );

        final report = const MachOParser().parseFile(file);

        expect(
          report.objcMethods.single.name,
          'userNotificationCenter:openSettingsForNotification:',
        );
        expect(
          report.objcMethods.single.className,
          'RelativeNotificationDelegate',
        );
      },
    );

    test('resolves Objective-C small method lists from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithObjCSmallMethodList(
          className: 'CompactDelegate',
          methodNames: ['locationManager:didUpdateLocations:'],
        ),
      );

      expect(
        report.objcMethods.single.name,
        'locationManager:didUpdateLocations:',
      );
      expect(report.objcMethods.single.className, 'CompactDelegate');
      expect(
        report.objcMethods.single.sourceSection,
        '__DATA_CONST.__objc_const',
      );
    });

    test('resolves Objective-C metaclass method lists from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithObjCMetaclassMethodList(
          className: 'RunnerViewController',
          methodNames: ['sharedRegistrar'],
        ),
      );

      expect(report.objcMethods.map((method) => method.name), [
        'sharedRegistrar',
      ]);
      expect(report.objcMethods.single.className, 'RunnerViewController');
      expect(
        report.objcMethods.single.sourceSection,
        '__DATA_CONST.__objc_const',
      );
    });

    test(
      'resolves Objective-C small method lists from the file-backed parser',
      () async {
        final root = await Directory.systemTemp.createTemp('fal_macho_');
        addTearDown(() => root.deleteSync(recursive: true));

        final file = File('${root.path}/Runner')
          ..writeAsBytesSync(
            thinMachOWithObjCSmallMethodList(
              className: 'CompactNotificationDelegate',
              methodNames: [
                'userNotificationCenter:willPresentNotification:withCompletionHandler:',
              ],
              paddingBeforeData: 4096,
            ),
          );

        final report = const MachOParser().parseFile(file);

        expect(
          report.objcMethods.single.name,
          'userNotificationCenter:willPresentNotification:withCompletionHandler:',
        );
        expect(
          report.objcMethods.single.className,
          'CompactNotificationDelegate',
        );
      },
    );

    test('resolves Objective-C category method lists from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithObjCCategoryMethodList(
          className: 'RunnerViewController',
          categoryName: 'Location',
          instanceMethodNames: ['requestWhenInUseAuthorization'],
          classMethodNames: ['sharedLocationController'],
        ),
      );

      expect(
        report.objcMethods.map((method) => method.name),
        containsAll([
          'requestWhenInUseAuthorization',
          'sharedLocationController',
        ]),
      );
      expect(
        report.objcMethods.map((method) => method.className),
        everyElement('RunnerViewController'),
      );
      expect(
        report.objcMethods.map((method) => method.sourceSection),
        everyElement('__DATA_CONST.__objc_const'),
      );
    });

    test('resolves Objective-C category metadata from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithObjCCategoryMethodList(
          className: 'RunnerViewController',
          categoryName: 'Location',
          instanceMethodNames: ['requestWhenInUseAuthorization'],
          classMethodNames: const [],
        ),
      );

      expect(report.objcCategories.single.name, 'Location');
      expect(report.objcCategories.single.className, 'RunnerViewController');
      expect(
        report.objcCategories.single.sourceSection,
        '__DATA_CONST.__objc_catlist',
      );
    });

    test('resolves Objective-C ivar and property lists from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithObjCFieldMetadata(
          className: 'RunnerViewController',
          ivars: [
            (name: '_locationManager', typeEncoding: r'@"CLLocationManager"'),
          ],
          properties: [
            (
              name: 'locationManager',
              attributes: r'T@"CLLocationManager",N,V_locationManager',
            ),
          ],
        ),
      );

      expect(report.objcIvars.map((ivar) => ivar.name), ['_locationManager']);
      expect(report.objcIvars.single.typeEncoding, r'@"CLLocationManager"');
      expect(report.objcIvars.single.className, 'RunnerViewController');
      expect(
        report.objcIvars.single.sourceSection,
        '__DATA_CONST.__objc_const',
      );
      expect(report.objcProperties.map((property) => property.name), [
        'locationManager',
      ]);
      expect(
        report.objcProperties.single.attributes,
        r'T@"CLLocationManager",N,V_locationManager',
      );
      expect(report.objcProperties.single.className, 'RunnerViewController');
      expect(
        report.objcProperties.single.sourceSection,
        '__DATA_CONST.__objc_const',
      );
    });

    test('resolves Objective-C category property lists from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithObjCCategoryPropertyList(
          className: 'RunnerViewController',
          categoryName: 'Location',
          properties: [
            (name: 'locationManager', attributes: r'T@"CLLocationManager",N'),
          ],
        ),
      );

      expect(report.objcProperties.map((property) => property.name), [
        'locationManager',
      ]);
      expect(
        report.objcProperties.single.attributes,
        r'T@"CLLocationManager",N',
      );
      expect(report.objcProperties.single.className, 'RunnerViewController');
      expect(
        report.objcProperties.single.sourceSection,
        '__DATA_CONST.__objc_const',
      );
    });

    test('resolves Objective-C category class property lists from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithObjCCategoryPropertyList(
          className: 'RunnerViewController',
          categoryName: 'Notifications',
          classProperty: true,
          properties: [
            (
              name: 'notificationCenter',
              attributes: r'T@"UNUserNotificationCenter",R',
            ),
          ],
        ),
      );

      expect(report.objcProperties.map((property) => property.name), [
        'notificationCenter',
      ]);
      expect(
        report.objcProperties.single.attributes,
        r'T@"UNUserNotificationCenter",R',
      );
      expect(report.objcProperties.single.className, 'RunnerViewController');
      expect(
        report.objcProperties.single.sourceSection,
        '__DATA_CONST.__objc_const',
      );
    });

    test('resolves Objective-C protocol property lists from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithObjCProtocolPropertyList(
          protocolName: 'FlutterPlugin',
          properties: [(name: 'registrar', attributes: r'T@"NSObject",R')],
        ),
      );

      expect(report.objcProperties.map((property) => property.name), [
        'registrar',
      ]);
      expect(report.objcProperties.single.attributes, r'T@"NSObject",R');
      expect(report.objcProperties.single.className, 'FlutterPlugin');
      expect(
        report.objcProperties.single.sourceSection,
        '__DATA_CONST.__objc_const',
      );
    });

    test(
      'resolves inherited Objective-C protocol property lists from bytes',
      () {
        final report = const MachOParser().parse(
          thinMachOWithObjCInheritedProtocolPropertyList(
            protocolName: 'FlutterPlugin',
            inheritedProtocolName: 'UIApplicationDelegate',
            inheritedProperties: [
              (name: 'window', attributes: r'T@"UIWindow",R'),
            ],
          ),
        );

        expect(report.objcProperties.map((property) => property.name), [
          'window',
        ]);
        expect(report.objcProperties.single.attributes, r'T@"UIWindow",R');
        expect(report.objcProperties.single.className, 'UIApplicationDelegate');
        expect(
          report.objcProperties.single.sourceSection,
          '__DATA_CONST.__objc_const',
        );
      },
    );

    test('resolves Objective-C protocol class property lists from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithObjCProtocolPropertyList(
          protocolName: 'FlutterPlugin',
          classProperty: true,
          properties: [
            (name: 'sharedRegistrar', attributes: r'T@"NSObject",R'),
          ],
        ),
      );

      expect(report.objcProperties.map((property) => property.name), [
        'sharedRegistrar',
      ]);
      expect(report.objcProperties.single.attributes, r'T@"NSObject",R');
      expect(report.objcProperties.single.className, 'FlutterPlugin');
      expect(
        report.objcProperties.single.sourceSection,
        '__DATA_CONST.__objc_const',
      );
    });

    test('resolves Objective-C metaclass property lists from bytes', () {
      final report = const MachOParser().parse(
        thinMachOWithObjCMetaclassPropertyList(
          className: 'RunnerViewController',
          properties: [
            (
              name: 'notificationCenter',
              attributes: r'T@"UNUserNotificationCenter",R',
            ),
          ],
        ),
      );

      expect(report.objcProperties.map((property) => property.name), [
        'notificationCenter',
      ]);
      expect(
        report.objcProperties.single.attributes,
        r'T@"UNUserNotificationCenter",R',
      );
      expect(report.objcProperties.single.className, 'RunnerViewController');
      expect(
        report.objcProperties.single.sourceSection,
        '__DATA_CONST.__objc_const',
      );
    });

    test(
      'resolves Objective-C class protocol properties without class properties',
      () {
        final report = const MachOParser().parse(
          thinMachOWithObjCClassProtocolPropertyList(
            className: 'RunnerAppDelegate',
            protocolName: 'FlutterPlugin',
            properties: [(name: 'registrar', attributes: r'T@"NSObject",R')],
          ),
        );

        expect(report.objcProperties.map((property) => property.name), [
          'registrar',
        ]);
        expect(report.objcProperties.single.attributes, r'T@"NSObject",R');
        expect(report.objcProperties.single.className, 'FlutterPlugin');
        expect(
          report.objcProperties.single.sourceSection,
          '__DATA_CONST.__objc_const',
        );
      },
    );

    test(
      'resolves Objective-C category method lists from the file-backed parser',
      () async {
        final root = await Directory.systemTemp.createTemp('fal_macho_');
        addTearDown(() => root.deleteSync(recursive: true));

        final file = File('${root.path}/Runner')
          ..writeAsBytesSync(
            thinMachOWithObjCCategoryMethodList(
              className: 'NotificationDelegate',
              categoryName: 'Authorization',
              instanceMethodNames: [
                'userNotificationCenter:openSettingsForNotification:',
              ],
              classMethodNames: const [],
              paddingBeforeData: 4096,
            ),
          );

        final report = const MachOParser().parseFile(file);

        expect(
          report.objcMethods.single.name,
          'userNotificationCenter:openSettingsForNotification:',
        );
        expect(report.objcMethods.single.className, 'NotificationDelegate');
      },
    );

    test(
      'resolves Objective-C category metadata from the file-backed parser',
      () async {
        final root = await Directory.systemTemp.createTemp('fal_macho_');
        addTearDown(() => root.deleteSync(recursive: true));

        final file = File('${root.path}/Runner')
          ..writeAsBytesSync(
            thinMachOWithObjCCategoryMethodList(
              className: 'NotificationDelegate',
              categoryName: 'Authorization',
              instanceMethodNames: ['authorizationStatus'],
              classMethodNames: const [],
              paddingBeforeData: 4096,
            ),
          );

        final report = const MachOParser().parseFile(file);

        expect(report.objcCategories.single.name, 'Authorization');
        expect(report.objcCategories.single.className, 'NotificationDelegate');
      },
    );

    test('ignores non-Mach-O bytes', () {
      final report = const MachOParser().parse(latin1.encode('not a binary'));

      expect(report.linkedDylibs, isEmpty);
    });

    test('stops on malformed load command sizes', () {
      final report = const MachOParser().parse([
        ...machOHeader64(ncmds: 1, sizeofcmds: 8),
        0x0c,
        0x00,
        0x00,
        0x00,
        0x07,
        0x00,
        0x00,
        0x00,
      ]);

      expect(report.linkedDylibs, isEmpty);
    });
  });
}

List<int> thinMachO(
  List<List<int>> commands, {
  int cpuType = 0x0100000c,
  int cpuSubtype = 0,
}) {
  return [
    ...machOHeader64(
      ncmds: commands.length,
      sizeofcmds: commands.fold(0, (total, command) => total + command.length),
      cpuType: cpuType,
      cpuSubtype: cpuSubtype,
    ),
    for (final command in commands) ...command,
  ];
}

List<int> thinMachOWithSymbolTable(
  List<String> symbols, {
  int paddingBeforeSymbolTable = 0,
}) {
  final stringTable = stringTableBytes(symbols);
  final symbolEntries = <int>[];
  var stringIndex = 1;
  for (final symbol in symbols) {
    symbolEntries.addAll(nlist64Bytes(stringIndex));
    stringIndex += latin1.encode(symbol).length + 1;
  }

  final symoff = 32 + 24 + paddingBeforeSymbolTable;
  final stroff = symoff + symbolEntries.length;
  return [
    ...machOHeader64(ncmds: 1, sizeofcmds: 24),
    ...machoSymtabCommand(
      symbolOffset: symoff,
      symbolCount: symbols.length,
      stringOffset: stroff,
      stringSize: stringTable.length,
    ),
    ...List.filled(paddingBeforeSymbolTable, 0),
    ...symbolEntries,
    ...stringTable,
  ];
}

List<int> thinMachOWithDyldBindSymbols(
  List<String> symbols, {
  int paddingBeforeBindInfo = 0,
}) {
  final bindInfo = dyldBindInfoBytes(symbols);
  const commandsSize = 48;
  final bindOffset = 32 + commandsSize + paddingBeforeBindInfo;
  final command = machoDyldInfoCommand(
    bindOffset: bindOffset,
    bindSize: bindInfo.length,
  );

  return [
    ...machOHeader64(ncmds: 1, sizeofcmds: command.length),
    ...command,
    ...List.filled(paddingBeforeBindInfo, 0),
    ...bindInfo,
  ];
}

List<int> thinMachOWithChainedFixupImports(
  List<String> symbols, {
  int importFormat = 1,
  int symbolsFormat = 0,
  bool corruptCompressedSymbols = false,
  int paddingBeforeChainedFixups = 0,
  bool includeStartsMetadata = false,
}) {
  final chainedFixups = chainedFixupsPayload(
    symbols,
    importFormat: importFormat,
    corruptCompressedSymbols: corruptCompressedSymbols,
    symbolsFormat: symbolsFormat,
    includeStartsMetadata: includeStartsMetadata,
  );
  const commandsSize = 16;
  final dataOffset = 32 + commandsSize + paddingBeforeChainedFixups;
  final command = machoChainedFixupsCommand(
    dataOffset: dataOffset,
    dataSize: chainedFixups.length,
  );

  return [
    ...machOHeader64(ncmds: 1, sizeofcmds: command.length),
    ...command,
    ...List.filled(paddingBeforeChainedFixups, 0),
    ...chainedFixups,
  ];
}

List<int> thinMachOWithFunctionStarts(List<int> offsets) {
  final functionStarts = functionStartsBytes(offsets);
  const commandsSize = 16;
  final dataOffset = 32 + commandsSize;
  final command = machoFunctionStartsCommand(
    dataOffset: dataOffset,
    dataSize: functionStarts.length,
  );

  return [
    ...machOHeader64(ncmds: 1, sizeofcmds: command.length),
    ...command,
    ...functionStarts,
  ];
}

List<int> thinMachOWithDataInCode(
  List<({int offset, int length, int kind})> entries, {
  int paddingBeforeDataInCode = 0,
}) {
  final dataInCode = dataInCodeBytes(entries);
  const commandsSize = 16;
  final dataOffset = 32 + commandsSize + paddingBeforeDataInCode;
  final command = machoDataInCodeCommand(
    dataOffset: dataOffset,
    dataSize: dataInCode.length,
  );

  return [
    ...machOHeader64(ncmds: 1, sizeofcmds: command.length),
    ...command,
    ...List.filled(paddingBeforeDataInCode, 0),
    ...dataInCode,
  ];
}

List<int> thinMachOWithDyldExportsTrie(
  List<String> symbols, {
  int paddingBeforeExportsTrie = 0,
}) {
  final exportsTrie = dyldExportsTrieBytes(symbols);
  const commandsSize = 16;
  final dataOffset = 32 + commandsSize + paddingBeforeExportsTrie;
  final command = machoExportsTrieCommand(
    dataOffset: dataOffset,
    dataSize: exportsTrie.length,
  );

  return [
    ...machOHeader64(ncmds: 1, sizeofcmds: command.length),
    ...command,
    ...List.filled(paddingBeforeExportsTrie, 0),
    ...exportsTrie,
  ];
}

List<int> thinMachOWithDyldInfoExportsTrie(List<String> symbols) {
  final exportsTrie = dyldExportsTrieBytes(symbols);
  const commandsSize = 48;
  final exportOffset = 32 + commandsSize;
  final command = machoDyldInfoCommand(
    bindOffset: 0,
    bindSize: 0,
    exportOffset: exportOffset,
    exportSize: exportsTrie.length,
  );

  return [
    ...machOHeader64(ncmds: 1, sizeofcmds: command.length),
    ...command,
    ...exportsTrie,
  ];
}

List<int> thinMachOWithCStringSection({
  required String segmentName,
  required String sectionName,
  required List<String> values,
  int paddingBeforeStrings = 0,
}) {
  final sectionData = cStringBytes(values);
  final commandSize = 72 + 80;
  final sectionOffset = 32 + commandSize + paddingBeforeStrings;
  final command = machoSegment64RangeCommand(segmentName, [
    (
      name: sectionName,
      segmentName: segmentName,
      fileOffset: sectionOffset,
      size: sectionData.length,
    ),
  ]);

  return [
    ...machOHeader64(ncmds: 1, sizeofcmds: command.length),
    ...command,
    ...List.filled(paddingBeforeStrings, 0),
    ...sectionData,
  ];
}

List<int> thinMachOWithSwiftTypeDescriptors(
  List<String> typeNames, {
  int paddingBeforeData = 0,
}) {
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
      ...u32(0), // flags
      ...u32(0), // parent
      ...u32(nameAddress - (currentDescriptorAddress + 8)),
      ...u32(0), // access function
      ...latin1.encode(typeNames[i]),
      0,
    ]);
  }

  final commandSize = 72 + 2 * 80;
  final typesOffset = 32 + commandSize + paddingBeforeData;
  final descriptorOffset = typesOffset + typeEntries.length;
  final command = machoSegment64AddressRangeCommand('__TEXT', [
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
    ...machOHeader64(ncmds: 1, sizeofcmds: command.length),
    ...command,
    ...List.filled(paddingBeforeData, 0),
    ...typeEntries,
    ...descriptorData,
  ];
}

List<int> thinMachOWithSwiftProtocolConformances(
  List<({String typeName, String protocolName})> conformances, {
  int paddingBeforeData = 0,
}) {
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
      ...u32(0), // witness table
      ...u32(0), // conformance flags
      ...u32(0), // type flags
      ...u32(0), // type parent
      ...u32(typeNameAddress - (typeDescriptorAddress + 8)),
      ...u32(0), // type access function
      ...latin1.encode(conformances[i].typeName),
      0,
      ...u32(0), // protocol flags
      ...u32(0), // protocol parent
      ...u32(protocolNameAddress - (protocolDescriptorAddress + 8)),
      ...u32(0), // protocol requirements signature
      ...latin1.encode(conformances[i].protocolName),
      0,
    ]);
  }

  final commandSize = 72 + 2 * 80;
  final protoOffset = 32 + commandSize + paddingBeforeData;
  final descriptorOffset = protoOffset + protoEntries.length;
  final command = machoSegment64AddressRangeCommand('__TEXT', [
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
    ...machOHeader64(ncmds: 1, sizeofcmds: command.length),
    ...command,
    ...List.filled(paddingBeforeData, 0),
    ...protoEntries,
    ...descriptorData,
  ];
}

List<int> thinMachOWithSwiftProtocolDescriptors(
  List<String> protocolNames, {
  int paddingBeforeData = 0,
}) {
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
      ...u32(0), // flags
      ...u32(0), // parent
      ...u32(nameAddress - (currentDescriptorAddress + 8)),
      ...u32(0), // requirements signature
      ...latin1.encode(protocolNames[i]),
      0,
    ]);
  }

  final commandSize = 72 + 2 * 80;
  final protosOffset = 32 + commandSize + paddingBeforeData;
  final descriptorOffset = protosOffset + protoEntries.length;
  final command = machoSegment64AddressRangeCommand('__TEXT', [
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
    ...machOHeader64(ncmds: 1, sizeofcmds: command.length),
    ...command,
    ...List.filled(paddingBeforeData, 0),
    ...protoEntries,
    ...descriptorData,
  ];
}

List<int> thinMachOWithSwiftFieldDescriptors(
  List<({String ownerTypeName, List<({String name, String typeName})> fields})>
  descriptors, {
  String? superclassTypeName,
  int paddingBeforeData = 0,
}) {
  final fieldmdAddress = 0x100000100;
  final reflstrAddress = 0x100000800;
  final typerefAddress = 0x100001000;
  final fieldNames = [
    for (final descriptor in descriptors)
      for (final field in descriptor.fields) field.name,
  ];
  final typeNames = [
    for (final descriptor in descriptors) ...[
      descriptor.ownerTypeName,
      ?superclassTypeName,
      for (final field in descriptor.fields) field.typeName,
    ],
  ];
  final reflstrData = cStringBytes(fieldNames);
  final typerefData = cStringBytes(typeNames);
  final fieldNameOffsets = stringOffsets(fieldNames);
  final typeNameOffsets = stringOffsets(typeNames);
  final fieldmdData = <int>[];
  var fieldNameIndex = 0;
  var typeNameIndex = 0;

  for (final descriptor in descriptors) {
    final descriptorAddress = fieldmdAddress + fieldmdData.length;
    final ownerTypeNameAddress =
        typerefAddress + typeNameOffsets[typeNameIndex];
    typeNameIndex += 1;
    final superclassTypeNameAddress = superclassTypeName == null
        ? 0
        : typerefAddress + typeNameOffsets[typeNameIndex];
    if (superclassTypeName != null) typeNameIndex += 1;
    fieldmdData.addAll([
      ...u32(ownerTypeNameAddress - descriptorAddress),
      ...u32(
        superclassTypeNameAddress == 0
            ? 0
            : superclassTypeNameAddress - (descriptorAddress + 4),
      ),
      ...u16(0), // kind
      ...u16(12), // field record size
      ...u32(descriptor.fields.length),
    ]);

    for (var i = 0; i < descriptor.fields.length; i += 1) {
      final recordAddress = descriptorAddress + 16 + i * 12;
      final fieldTypeAddress = typerefAddress + typeNameOffsets[typeNameIndex];
      final fieldNameAddress =
          reflstrAddress + fieldNameOffsets[fieldNameIndex];
      typeNameIndex += 1;
      fieldNameIndex += 1;
      fieldmdData.addAll([
        ...u32(0), // flags
        ...u32(fieldTypeAddress - (recordAddress + 4)),
        ...u32(fieldNameAddress - (recordAddress + 8)),
      ]);
    }
  }

  final commandSize = 72 + 3 * 80;
  final fieldmdOffset = 32 + commandSize + paddingBeforeData;
  final reflstrOffset = fieldmdOffset + fieldmdData.length;
  final typerefOffset = reflstrOffset + reflstrData.length;
  final command = machoSegment64AddressRangeCommand('__TEXT', [
    (
      name: '__swift5_fieldmd',
      segmentName: '__TEXT',
      address: fieldmdAddress,
      fileOffset: fieldmdOffset,
      size: fieldmdData.length,
    ),
    (
      name: '__swift5_reflstr',
      segmentName: '__TEXT',
      address: reflstrAddress,
      fileOffset: reflstrOffset,
      size: reflstrData.length,
    ),
    (
      name: '__swift5_typeref',
      segmentName: '__TEXT',
      address: typerefAddress,
      fileOffset: typerefOffset,
      size: typerefData.length,
    ),
  ]);

  return [
    ...machOHeader64(ncmds: 1, sizeofcmds: command.length),
    ...command,
    ...List.filled(paddingBeforeData, 0),
    ...fieldmdData,
    ...reflstrData,
    ...typerefData,
  ];
}

List<int> thinMachOWithObjCSelectorRefs(
  List<String> selectors, {
  int paddingBeforeData = 0,
  bool chainedPointers = false,
  bool authenticatedChainedPointers = false,
  bool authenticatedChainedBindPointers = false,
}) {
  final methnameAddress = 0x100000100;
  final selrefsAddress = 0x100000800;
  final methnameData = cStringBytes(selectors);
  final selectorOffsets = stringOffsets(selectors);
  final pointerData = [
    for (final selectorOffset in selectorOffsets)
      ...u64(
        authenticatedChainedBindPointers
            ? chainedPointerArm64eAuthBind(methnameAddress + selectorOffset)
            : authenticatedChainedPointers
            ? chainedPointerArm64eAuthRebaseOffset(
                methnameAddress + selectorOffset,
              )
            : chainedPointers
            ? chainedPointer64Offset(methnameAddress + selectorOffset)
            : methnameAddress + selectorOffset,
      ),
  ];
  final commandsSize = 2 * (72 + 80);
  final methnameOffset = 32 + commandsSize + paddingBeforeData;
  final selrefsOffset = methnameOffset + methnameData.length;
  final textCommand = machoSegment64AddressRangeCommand('__TEXT', [
    (
      name: '__objc_methname',
      segmentName: '__TEXT',
      address: methnameAddress,
      fileOffset: methnameOffset,
      size: methnameData.length,
    ),
  ]);
  final dataCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_selrefs',
      segmentName: '__DATA_CONST',
      address: selrefsAddress,
      fileOffset: selrefsOffset,
      size: pointerData.length,
    ),
  ]);

  return [
    ...machOHeader64(
      ncmds: 2,
      sizeofcmds: textCommand.length + dataCommand.length,
    ),
    ...textCommand,
    ...dataCommand,
    ...List.filled(paddingBeforeData, 0),
    ...methnameData,
    ...pointerData,
  ];
}

int chainedPointer64Offset(int address, {int imageBase = 0x100000000}) {
  return 0x0010000000000000 | (address - imageBase);
}

int chainedPointerArm64eAuthRebaseOffset(
  int address, {
  int imageBase = 0x100000000,
}) {
  const diversity = 0x1234;
  const authBit = 1 << 63;
  return authBit | (diversity << 32) | (address - imageBase);
}

int chainedPointerArm64eAuthBind(int address, {int imageBase = 0x100000000}) {
  const diversity = 0x1230;
  const bindBit = 1 << 62;
  const authBit = 1 << 63;
  return authBit | bindBit | (diversity << 32) | (address - imageBase);
}

List<int> thinMachOWithObjCClassRef(
  String className, {
  String? superclassName,
  int paddingBeforeData = 0,
}) {
  final classNameAddress = 0x100000100;
  final classAddress = 0x100000800;
  final classRoAddress = 0x100001000;
  final classRefAddress = 0x100001800;
  final classNames = [className, ?superclassName];
  final classNameData = cStringBytes(classNames);
  final classNameOffsets = stringOffsets(classNames);
  final superclassAddress = superclassName == null ? 0 : classAddress + 40;
  final classRoData = objcClassRo64Bytes(
    classNameAddress + classNameOffsets[0],
  );
  final superclassRoAddress = classRoAddress + classRoData.length;
  final classData = [
    ...objcClass64Bytes(
      classRoAddress | 0x1,
      superclassAddress: superclassAddress,
    ),
    if (superclassName != null) ...objcClass64Bytes(superclassRoAddress),
  ];
  final superclassRoData = superclassName == null
      ? <int>[]
      : objcClassRo64Bytes(classNameAddress + classNameOffsets[1]);
  final classRefData = u64(classAddress);
  final commandsSize = 4 * (72 + 80);
  final classNameOffset = 32 + commandsSize + paddingBeforeData;
  final classOffset = classNameOffset + classNameData.length;
  final classRoOffset = classOffset + classData.length;
  final classRefOffset =
      classRoOffset + classRoData.length + superclassRoData.length;

  final textCommand = machoSegment64AddressRangeCommand('__TEXT', [
    (
      name: '__objc_classname',
      segmentName: '__TEXT',
      address: classNameAddress,
      fileOffset: classNameOffset,
      size: classNameData.length,
    ),
  ]);
  final dataCommand = machoSegment64AddressRangeCommand('__DATA', [
    (
      name: '__objc_data',
      segmentName: '__DATA',
      address: classAddress,
      fileOffset: classOffset,
      size: classData.length,
    ),
  ]);
  final constCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_const',
      segmentName: '__DATA_CONST',
      address: classRoAddress,
      fileOffset: classRoOffset,
      size: classRoData.length + superclassRoData.length,
    ),
  ]);
  final refsCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_classrefs',
      segmentName: '__DATA_CONST',
      address: classRefAddress,
      fileOffset: classRefOffset,
      size: classRefData.length,
    ),
  ]);

  return [
    ...machOHeader64(
      ncmds: 4,
      sizeofcmds:
          textCommand.length +
          dataCommand.length +
          constCommand.length +
          refsCommand.length,
    ),
    ...textCommand,
    ...dataCommand,
    ...constCommand,
    ...refsCommand,
    ...List.filled(paddingBeforeData, 0),
    ...classNameData,
    ...classData,
    ...classRoData,
    ...superclassRoData,
    ...classRefData,
  ];
}

List<int> thinMachOWithObjCProtocolRefs(
  List<String> protocolNames, {
  String sectionName = '__objc_protolist',
  int paddingBeforeData = 0,
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
  final nameOffset = 32 + commandsSize + paddingBeforeData;
  final protocolOffset = nameOffset + namesData.length;
  final protocolListOffset = protocolOffset + protocolData.length;

  final textCommand = machoSegment64AddressRangeCommand('__TEXT', [
    (
      name: '__objc_classname',
      segmentName: '__TEXT',
      address: nameAddress,
      fileOffset: nameOffset,
      size: namesData.length,
    ),
  ]);
  final constCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_const',
      segmentName: '__DATA_CONST',
      address: protocolAddress,
      fileOffset: protocolOffset,
      size: protocolData.length,
    ),
  ]);
  final protocolListCommand =
      machoSegment64AddressRangeCommand('__DATA_CONST', [
        (
          name: sectionName,
          segmentName: '__DATA_CONST',
          address: protocolListAddress,
          fileOffset: protocolListOffset,
          size: protocolListData.length,
        ),
      ]);

  return [
    ...machOHeader64(
      ncmds: 3,
      sizeofcmds:
          textCommand.length + constCommand.length + protocolListCommand.length,
    ),
    ...textCommand,
    ...constCommand,
    ...protocolListCommand,
    ...List.filled(paddingBeforeData, 0),
    ...namesData,
    ...protocolData,
    ...protocolListData,
  ];
}

List<int> thinMachOWithObjCProtocolInheritance({
  required String protocolName,
  required String inheritedProtocolName,
  int paddingBeforeData = 0,
}) {
  final protocolNameAddress = 0x100000100;
  final protocolAddress = 0x100001000;
  final inheritedProtocolAddress = protocolAddress + 64;
  final inheritedProtocolListAddress = inheritedProtocolAddress + 64;
  final topLevelProtocolListAddress = 0x100002000;
  final namesData = cStringBytes([protocolName, inheritedProtocolName]);
  final nameOffsets = stringOffsets([protocolName, inheritedProtocolName]);
  final protocolData = [
    ...objcProtocol64Bytes(
      protocolNameAddress + nameOffsets[0],
      protocolsAddress: inheritedProtocolListAddress,
    ),
    ...objcProtocol64Bytes(protocolNameAddress + nameOffsets[1]),
    ...objcProtocolList64Bytes([inheritedProtocolAddress]),
  ];
  final topLevelProtocolListData = u64(protocolAddress);
  final commandsSize = 3 * (72 + 80);
  final nameOffset = 32 + commandsSize + paddingBeforeData;
  final protocolOffset = nameOffset + namesData.length;
  final topLevelProtocolListOffset = protocolOffset + protocolData.length;

  final textCommand = machoSegment64AddressRangeCommand('__TEXT', [
    (
      name: '__objc_classname',
      segmentName: '__TEXT',
      address: protocolNameAddress,
      fileOffset: nameOffset,
      size: namesData.length,
    ),
  ]);
  final constCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_const',
      segmentName: '__DATA_CONST',
      address: protocolAddress,
      fileOffset: protocolOffset,
      size: protocolData.length,
    ),
  ]);
  final protocolListCommand =
      machoSegment64AddressRangeCommand('__DATA_CONST', [
        (
          name: '__objc_protolist',
          segmentName: '__DATA_CONST',
          address: topLevelProtocolListAddress,
          fileOffset: topLevelProtocolListOffset,
          size: topLevelProtocolListData.length,
        ),
      ]);

  return [
    ...machOHeader64(
      ncmds: 3,
      sizeofcmds:
          textCommand.length + constCommand.length + protocolListCommand.length,
    ),
    ...textCommand,
    ...constCommand,
    ...protocolListCommand,
    ...List.filled(paddingBeforeData, 0),
    ...namesData,
    ...protocolData,
    ...topLevelProtocolListData,
  ];
}

List<int> thinMachOWithObjCClassProtocolList({
  required String className,
  required List<String> protocolNames,
  int paddingBeforeData = 0,
}) {
  final classNameAddress = 0x100000100;
  final protocolNameAddress = 0x100000400;
  final classAddress = 0x100000800;
  final classRoAddress = 0x100001000;
  final classListAddress = 0x100001800;
  final classNameData = cStringBytes([className]);
  final protocolNameData = cStringBytes(protocolNames);
  final protocolNameOffsets = stringOffsets(protocolNames);
  final classData = objcClass64Bytes(classRoAddress);
  final protocolAddress = classRoAddress + 48;
  final protocolListAddress = protocolAddress + protocolNames.length * 64;
  final classRoData = objcClassRo64Bytes(
    classNameAddress,
    baseProtocolsAddress: protocolListAddress,
  );
  final protocolData = [
    for (final protocolNameOffset in protocolNameOffsets)
      ...objcProtocol64Bytes(protocolNameAddress + protocolNameOffset),
  ];
  final protocolListData = objcProtocolList64Bytes([
    for (var i = 0; i < protocolNames.length; i += 1) protocolAddress + i * 64,
  ]);
  final classListData = u64(classAddress);
  final commandsSize = (72 + 2 * 80) + 3 * (72 + 80);
  final classNameOffset = 32 + commandsSize + paddingBeforeData;
  final protocolNameOffset = classNameOffset + classNameData.length;
  final classOffset = protocolNameOffset + protocolNameData.length;
  final classRoOffset = classOffset + classData.length;
  final classListOffset =
      classRoOffset +
      classRoData.length +
      protocolData.length +
      protocolListData.length;

  final textCommand = machoSegment64AddressRangeCommand('__TEXT', [
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
      address: protocolNameAddress,
      fileOffset: protocolNameOffset,
      size: protocolNameData.length,
    ),
  ]);
  final dataCommand = machoSegment64AddressRangeCommand('__DATA', [
    (
      name: '__objc_data',
      segmentName: '__DATA',
      address: classAddress,
      fileOffset: classOffset,
      size: classData.length,
    ),
  ]);
  final constCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_const',
      segmentName: '__DATA_CONST',
      address: classRoAddress,
      fileOffset: classRoOffset,
      size: classRoData.length + protocolData.length + protocolListData.length,
    ),
  ]);
  final classListCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_classlist',
      segmentName: '__DATA_CONST',
      address: classListAddress,
      fileOffset: classListOffset,
      size: classListData.length,
    ),
  ]);

  return [
    ...machOHeader64(
      ncmds: 4,
      sizeofcmds:
          textCommand.length +
          dataCommand.length +
          constCommand.length +
          classListCommand.length,
    ),
    ...textCommand,
    ...dataCommand,
    ...constCommand,
    ...classListCommand,
    ...List.filled(paddingBeforeData, 0),
    ...classNameData,
    ...protocolNameData,
    ...classData,
    ...classRoData,
    ...protocolData,
    ...protocolListData,
    ...classListData,
  ];
}

List<int> thinMachOWithObjCProtocolMethodList({
  required String protocolName,
  required List<String> methodNames,
  int paddingBeforeData = 0,
}) {
  final protocolNameAddress = 0x100000100;
  final methodNameAddress = 0x100000500;
  final protocolAddress = 0x100001000;
  final protocolListAddress = 0x100002000;
  final protocolNameData = cStringBytes([protocolName]);
  final methodNameData = cStringBytes(methodNames);
  final methodNameOffsets = stringOffsets(methodNames);
  final methodListAddress = protocolAddress + 64;
  final methodListData = objcMethodList64Bytes([
    for (final methodNameOffset in methodNameOffsets)
      methodNameAddress + methodNameOffset,
  ]);
  final protocolData = objcProtocol64Bytes(
    protocolNameAddress,
    instanceMethodsAddress: methodListAddress,
  );
  final protocolListData = u64(protocolAddress);
  final commandsSize = (72 + 2 * 80) + 2 * (72 + 80);
  final protocolNameOffset = 32 + commandsSize + paddingBeforeData;
  final methodNameOffset = protocolNameOffset + protocolNameData.length;
  final protocolOffset = methodNameOffset + methodNameData.length;
  final methodListOffset = protocolOffset + protocolData.length;
  final protocolListOffset = methodListOffset + methodListData.length;

  final textCommand = machoSegment64AddressRangeCommand('__TEXT', [
    (
      name: '__objc_classname',
      segmentName: '__TEXT',
      address: protocolNameAddress,
      fileOffset: protocolNameOffset,
      size: protocolNameData.length,
    ),
    (
      name: '__objc_methname',
      segmentName: '__TEXT',
      address: methodNameAddress,
      fileOffset: methodNameOffset,
      size: methodNameData.length,
    ),
  ]);
  final constCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_const',
      segmentName: '__DATA_CONST',
      address: protocolAddress,
      fileOffset: protocolOffset,
      size: protocolData.length + methodListData.length,
    ),
  ]);
  final protocolListCommand =
      machoSegment64AddressRangeCommand('__DATA_CONST', [
        (
          name: '__objc_protolist',
          segmentName: '__DATA_CONST',
          address: protocolListAddress,
          fileOffset: protocolListOffset,
          size: protocolListData.length,
        ),
      ]);

  return [
    ...machOHeader64(
      ncmds: 3,
      sizeofcmds:
          textCommand.length + constCommand.length + protocolListCommand.length,
    ),
    ...textCommand,
    ...constCommand,
    ...protocolListCommand,
    ...List.filled(paddingBeforeData, 0),
    ...protocolNameData,
    ...methodNameData,
    ...protocolData,
    ...methodListData,
    ...protocolListData,
  ];
}

List<int> thinMachOWithObjCInheritedProtocolMethodList({
  required String protocolName,
  required String inheritedProtocolName,
  required List<String> inheritedMethodNames,
  int paddingBeforeData = 0,
}) {
  final protocolNameAddress = 0x100000100;
  final methodNameAddress = 0x100000500;
  final protocolAddress = 0x100001000;
  final inheritedProtocolAddress = protocolAddress + 64;
  final inheritedProtocolListAddress = inheritedProtocolAddress + 64;
  final topLevelProtocolListAddress = 0x100002000;
  final protocolNamesData = cStringBytes([protocolName, inheritedProtocolName]);
  final protocolNameOffsets = stringOffsets([
    protocolName,
    inheritedProtocolName,
  ]);
  final methodNameData = cStringBytes(inheritedMethodNames);
  final methodNameOffsets = stringOffsets(inheritedMethodNames);
  final inheritedProtocolListData = objcProtocolList64Bytes([
    inheritedProtocolAddress,
  ]);
  final methodListAddress =
      inheritedProtocolListAddress + inheritedProtocolListData.length;
  final methodListData = objcMethodList64Bytes([
    for (final methodNameOffset in methodNameOffsets)
      methodNameAddress + methodNameOffset,
  ]);
  final protocolData = [
    ...objcProtocol64Bytes(
      protocolNameAddress + protocolNameOffsets[0],
      protocolsAddress: inheritedProtocolListAddress,
    ),
    ...objcProtocol64Bytes(
      protocolNameAddress + protocolNameOffsets[1],
      instanceMethodsAddress: methodListAddress,
    ),
    ...inheritedProtocolListData,
    ...methodListData,
  ];
  final topLevelProtocolListData = u64(protocolAddress);
  final commandsSize = (72 + 2 * 80) + 2 * (72 + 80);
  final protocolNameOffset = 32 + commandsSize + paddingBeforeData;
  final methodNameOffset = protocolNameOffset + protocolNamesData.length;
  final protocolOffset = methodNameOffset + methodNameData.length;
  final topLevelProtocolListOffset = protocolOffset + protocolData.length;

  final textCommand = machoSegment64AddressRangeCommand('__TEXT', [
    (
      name: '__objc_classname',
      segmentName: '__TEXT',
      address: protocolNameAddress,
      fileOffset: protocolNameOffset,
      size: protocolNamesData.length,
    ),
    (
      name: '__objc_methname',
      segmentName: '__TEXT',
      address: methodNameAddress,
      fileOffset: methodNameOffset,
      size: methodNameData.length,
    ),
  ]);
  final constCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_const',
      segmentName: '__DATA_CONST',
      address: protocolAddress,
      fileOffset: protocolOffset,
      size: protocolData.length,
    ),
  ]);
  final protocolListCommand =
      machoSegment64AddressRangeCommand('__DATA_CONST', [
        (
          name: '__objc_protolist',
          segmentName: '__DATA_CONST',
          address: topLevelProtocolListAddress,
          fileOffset: topLevelProtocolListOffset,
          size: topLevelProtocolListData.length,
        ),
      ]);

  return [
    ...machOHeader64(
      ncmds: 3,
      sizeofcmds:
          textCommand.length + constCommand.length + protocolListCommand.length,
    ),
    ...textCommand,
    ...constCommand,
    ...protocolListCommand,
    ...List.filled(paddingBeforeData, 0),
    ...protocolNamesData,
    ...methodNameData,
    ...protocolData,
    ...topLevelProtocolListData,
  ];
}

List<int> thinMachOWithObjCCategoryProtocolList({
  required String className,
  required String categoryName,
  required List<String> protocolNames,
  int paddingBeforeData = 0,
}) {
  final classNameAddress = 0x100000100;
  final protocolNameAddress = 0x100000500;
  final classAddress = 0x100000800;
  final classRoAddress = 0x100001000;
  final catlistAddress = 0x100001800;
  final namesData = cStringBytes([className, categoryName]);
  final nameOffsets = stringOffsets([className, categoryName]);
  final protocolNameData = cStringBytes(protocolNames);
  final protocolNameOffsets = stringOffsets(protocolNames);
  final categoryNameAddress = classNameAddress + nameOffsets[1];
  final classData = objcClass64Bytes(classRoAddress);
  final classRoData = objcClassRo64Bytes(classNameAddress);
  final categoryAddress = classRoAddress + classRoData.length;
  final protocolAddress = categoryAddress + 48;
  final protocolData = [
    for (final protocolNameOffset in protocolNameOffsets)
      ...objcProtocol64Bytes(protocolNameAddress + protocolNameOffset),
  ];
  final protocolListAddress = protocolAddress + protocolData.length;
  final protocolListData = objcProtocolList64Bytes([
    for (var i = 0; i < protocolNames.length; i += 1) protocolAddress + i * 64,
  ]);
  final categoryData = objcCategory64Bytes(
    nameAddress: categoryNameAddress,
    classAddress: classAddress,
    instanceMethodsAddress: 0,
    classMethodsAddress: 0,
    protocolsAddress: protocolListAddress,
  );
  final catlistData = u64(categoryAddress);
  final commandsSize = (72 + 2 * 80) + 3 * (72 + 80);
  final classNameOffset = 32 + commandsSize + paddingBeforeData;
  final protocolNameOffset = classNameOffset + namesData.length;
  final classOffset = protocolNameOffset + protocolNameData.length;
  final classRoOffset = classOffset + classData.length;
  final catlistOffset =
      classRoOffset +
      classRoData.length +
      categoryData.length +
      protocolData.length +
      protocolListData.length;

  final textCommand = machoSegment64AddressRangeCommand('__TEXT', [
    (
      name: '__objc_classname',
      segmentName: '__TEXT',
      address: classNameAddress,
      fileOffset: classNameOffset,
      size: namesData.length,
    ),
    (
      name: '__objc_methname',
      segmentName: '__TEXT',
      address: protocolNameAddress,
      fileOffset: protocolNameOffset,
      size: protocolNameData.length,
    ),
  ]);
  final dataCommand = machoSegment64AddressRangeCommand('__DATA', [
    (
      name: '__objc_data',
      segmentName: '__DATA',
      address: classAddress,
      fileOffset: classOffset,
      size: classData.length,
    ),
  ]);
  final constCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_const',
      segmentName: '__DATA_CONST',
      address: classRoAddress,
      fileOffset: classRoOffset,
      size:
          classRoData.length +
          categoryData.length +
          protocolData.length +
          protocolListData.length,
    ),
  ]);
  final catlistCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_catlist',
      segmentName: '__DATA_CONST',
      address: catlistAddress,
      fileOffset: catlistOffset,
      size: catlistData.length,
    ),
  ]);

  return [
    ...machOHeader64(
      ncmds: 4,
      sizeofcmds:
          textCommand.length +
          dataCommand.length +
          constCommand.length +
          catlistCommand.length,
    ),
    ...textCommand,
    ...dataCommand,
    ...constCommand,
    ...catlistCommand,
    ...List.filled(paddingBeforeData, 0),
    ...namesData,
    ...protocolNameData,
    ...classData,
    ...classRoData,
    ...categoryData,
    ...protocolData,
    ...protocolListData,
    ...catlistData,
  ];
}

List<int> thinMachOWithObjCMethodList({
  required String className,
  required List<String> methodNames,
  int paddingBeforeData = 0,
  bool relativeBaseMethods = false,
}) {
  final classNameAddress = 0x100000100;
  final methodNameAddress = 0x100000400;
  final classAddress = 0x100000800;
  final classRoAddress = 0x100001000;
  final classListAddress = 0x100001800;
  final classNameData = cStringBytes([className]);
  final methodNameData = cStringBytes(methodNames);
  final methodNameOffsets = stringOffsets(methodNames);
  final relativeMethodListsAddress = classRoAddress + 40;
  final methodListAddress = relativeBaseMethods
      ? relativeMethodListsAddress + 16
      : classRoAddress + 40;
  final classData = objcClass64Bytes(classRoAddress);
  final classRoData = objcClassRo64Bytes(
    classNameAddress,
    baseMethodsAddress: relativeBaseMethods
        ? relativeMethodListsAddress | 0x1
        : methodListAddress,
  );
  final relativeMethodListsData = relativeBaseMethods
      ? objcRelativeMethodListList64Bytes(
          listListAddress: relativeMethodListsAddress,
          methodListAddresses: [methodListAddress],
        )
      : <int>[];
  final methodListData = objcMethodList64Bytes([
    for (final methodNameOffset in methodNameOffsets)
      methodNameAddress + methodNameOffset,
  ]);
  final classListData = u64(classAddress);
  final commandsSize = (72 + 2 * 80) + 3 * (72 + 80);
  final classNameOffset = 32 + commandsSize + paddingBeforeData;
  final methodNameOffset = classNameOffset + classNameData.length;
  final classOffset = methodNameOffset + methodNameData.length;
  final classRoOffset = classOffset + classData.length;
  final relativeMethodListsOffset = classRoOffset + classRoData.length;
  final methodListOffset =
      relativeMethodListsOffset + relativeMethodListsData.length;
  final classListOffset = methodListOffset + methodListData.length;

  final textCommand = machoSegment64AddressRangeCommand('__TEXT', [
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
  final dataCommand = machoSegment64AddressRangeCommand('__DATA', [
    (
      name: '__objc_data',
      segmentName: '__DATA',
      address: classAddress,
      fileOffset: classOffset,
      size: classData.length,
    ),
  ]);
  final constCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_const',
      segmentName: '__DATA_CONST',
      address: classRoAddress,
      fileOffset: classRoOffset,
      size:
          classRoData.length +
          relativeMethodListsData.length +
          methodListData.length,
    ),
  ]);
  final listCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_classlist',
      segmentName: '__DATA_CONST',
      address: classListAddress,
      fileOffset: classListOffset,
      size: classListData.length,
    ),
  ]);

  return [
    ...machOHeader64(
      ncmds: 4,
      sizeofcmds:
          textCommand.length +
          dataCommand.length +
          constCommand.length +
          listCommand.length,
    ),
    ...textCommand,
    ...dataCommand,
    ...constCommand,
    ...listCommand,
    ...List.filled(paddingBeforeData, 0),
    ...classNameData,
    ...methodNameData,
    ...classData,
    ...classRoData,
    ...relativeMethodListsData,
    ...methodListData,
    ...classListData,
  ];
}

List<int> thinMachOWithObjCFieldMetadata({
  required String className,
  required List<({String name, String typeEncoding})> ivars,
  required List<({String name, String attributes})> properties,
  int paddingBeforeData = 0,
}) {
  final classNameAddress = 0x100000100;
  final fieldNameAddress = 0x100000400;
  final typeEncodingAddress = 0x100000800;
  final classAddress = 0x100001000;
  final classRoAddress = 0x100001800;
  final classListAddress = 0x100002800;
  final fieldNames = [
    for (final ivar in ivars) ivar.name,
    for (final property in properties) property.name,
  ];
  final typeEncodings = [
    for (final ivar in ivars) ivar.typeEncoding,
    for (final property in properties) property.attributes,
  ];
  final classNameData = cStringBytes([className]);
  final fieldNameData = cStringBytes(fieldNames);
  final typeEncodingData = cStringBytes(typeEncodings);
  final fieldNameOffsets = stringOffsets(fieldNames);
  final typeEncodingOffsets = stringOffsets(typeEncodings);
  var fieldNameIndex = 0;
  var typeEncodingIndex = 0;
  final classData = objcClass64Bytes(classRoAddress);
  final ivarListAddress = classRoAddress + 72;
  final ivarListData = objcIvarList64Bytes([
    for (final _ in ivars)
      (
        nameAddress: fieldNameAddress + fieldNameOffsets[fieldNameIndex++],
        typeAddress:
            typeEncodingAddress + typeEncodingOffsets[typeEncodingIndex++],
      ),
  ]);
  final propertyListAddress = ivarListAddress + ivarListData.length;
  final propertyListData = objcPropertyList64Bytes([
    for (final _ in properties)
      (
        nameAddress: fieldNameAddress + fieldNameOffsets[fieldNameIndex++],
        attributesAddress:
            typeEncodingAddress + typeEncodingOffsets[typeEncodingIndex++],
      ),
  ]);
  final classRoData = objcClassRo64Bytes(
    classNameAddress,
    ivarsAddress: ivarListAddress,
    basePropertiesAddress: propertyListAddress,
  );
  final classListData = u64(classAddress);
  final commandsSize = (72 + 3 * 80) + 3 * (72 + 80);
  final classNameOffset = 32 + commandsSize + paddingBeforeData;
  final fieldNameOffset = classNameOffset + classNameData.length;
  final typeEncodingOffset = fieldNameOffset + fieldNameData.length;
  final classOffset = typeEncodingOffset + typeEncodingData.length;
  final classRoOffset = classOffset + classData.length;
  final classListOffset =
      classRoOffset +
      classRoData.length +
      ivarListData.length +
      propertyListData.length;

  final textCommand = machoSegment64AddressRangeCommand('__TEXT', [
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
      address: fieldNameAddress,
      fileOffset: fieldNameOffset,
      size: fieldNameData.length,
    ),
    (
      name: '__objc_methtype',
      segmentName: '__TEXT',
      address: typeEncodingAddress,
      fileOffset: typeEncodingOffset,
      size: typeEncodingData.length,
    ),
  ]);
  final dataCommand = machoSegment64AddressRangeCommand('__DATA', [
    (
      name: '__objc_data',
      segmentName: '__DATA',
      address: classAddress,
      fileOffset: classOffset,
      size: classData.length,
    ),
  ]);
  final constCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_const',
      segmentName: '__DATA_CONST',
      address: classRoAddress,
      fileOffset: classRoOffset,
      size: classRoData.length + ivarListData.length + propertyListData.length,
    ),
  ]);
  final listCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_classlist',
      segmentName: '__DATA_CONST',
      address: classListAddress,
      fileOffset: classListOffset,
      size: classListData.length,
    ),
  ]);

  return [
    ...machOHeader64(
      ncmds: 4,
      sizeofcmds:
          textCommand.length +
          dataCommand.length +
          constCommand.length +
          listCommand.length,
    ),
    ...textCommand,
    ...dataCommand,
    ...constCommand,
    ...listCommand,
    ...List.filled(paddingBeforeData, 0),
    ...classNameData,
    ...fieldNameData,
    ...typeEncodingData,
    ...classData,
    ...classRoData,
    ...ivarListData,
    ...propertyListData,
    ...classListData,
  ];
}

List<int> thinMachOWithObjCCategoryPropertyList({
  required String className,
  required String categoryName,
  required List<({String name, String attributes})> properties,
  bool classProperty = false,
  int paddingBeforeData = 0,
}) {
  final classNameAddress = 0x100000100;
  final propertyNameAddress = 0x100000500;
  final propertyAttributesAddress = 0x100000900;
  final classAddress = 0x100001000;
  final classRoAddress = 0x100001800;
  final catlistAddress = 0x100002800;
  final namesData = cStringBytes([className, categoryName]);
  final nameOffsets = stringOffsets([className, categoryName]);
  final propertyNameData = cStringBytes([
    for (final property in properties) property.name,
  ]);
  final propertyNameOffsets = stringOffsets([
    for (final property in properties) property.name,
  ]);
  final propertyAttributesData = cStringBytes([
    for (final property in properties) property.attributes,
  ]);
  final propertyAttributesOffsets = stringOffsets([
    for (final property in properties) property.attributes,
  ]);
  final categoryNameAddress = classNameAddress + nameOffsets[1];
  final classData = objcClass64Bytes(classRoAddress);
  final classRoData = objcClassRo64Bytes(classNameAddress);
  final categoryAddress = classRoAddress + classRoData.length;
  final propertyListAddress = categoryAddress + (classProperty ? 56 : 48);
  final propertyListData = objcPropertyList64Bytes([
    for (var i = 0; i < properties.length; i += 1)
      (
        nameAddress: propertyNameAddress + propertyNameOffsets[i],
        attributesAddress:
            propertyAttributesAddress + propertyAttributesOffsets[i],
      ),
  ]);
  final categoryData = objcCategory64Bytes(
    nameAddress: categoryNameAddress,
    classAddress: classAddress,
    instanceMethodsAddress: 0,
    classMethodsAddress: 0,
    instancePropertiesAddress: classProperty ? 0 : propertyListAddress,
    classPropertiesAddress: classProperty ? propertyListAddress : 0,
  );
  final catlistData = u64(categoryAddress);
  final commandsSize = (72 + 3 * 80) + 3 * (72 + 80);
  final classNameOffset = 32 + commandsSize + paddingBeforeData;
  final propertyNameOffset = classNameOffset + namesData.length;
  final propertyAttributesOffset = propertyNameOffset + propertyNameData.length;
  final classOffset = propertyAttributesOffset + propertyAttributesData.length;
  final classRoOffset = classOffset + classData.length;
  final categoryOffset = classRoOffset + classRoData.length;
  final propertyListOffset = categoryOffset + categoryData.length;
  final catlistOffset = propertyListOffset + propertyListData.length;

  final textCommand = machoSegment64AddressRangeCommand('__TEXT', [
    (
      name: '__objc_classname',
      segmentName: '__TEXT',
      address: classNameAddress,
      fileOffset: classNameOffset,
      size: namesData.length,
    ),
    (
      name: '__objc_methname',
      segmentName: '__TEXT',
      address: propertyNameAddress,
      fileOffset: propertyNameOffset,
      size: propertyNameData.length,
    ),
    (
      name: '__objc_methtype',
      segmentName: '__TEXT',
      address: propertyAttributesAddress,
      fileOffset: propertyAttributesOffset,
      size: propertyAttributesData.length,
    ),
  ]);
  final dataCommand = machoSegment64AddressRangeCommand('__DATA', [
    (
      name: '__objc_data',
      segmentName: '__DATA',
      address: classAddress,
      fileOffset: classOffset,
      size: classData.length,
    ),
  ]);
  final constCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_const',
      segmentName: '__DATA_CONST',
      address: classRoAddress,
      fileOffset: classRoOffset,
      size: classRoData.length + categoryData.length + propertyListData.length,
    ),
  ]);
  final catlistCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_catlist',
      segmentName: '__DATA_CONST',
      address: catlistAddress,
      fileOffset: catlistOffset,
      size: catlistData.length,
    ),
  ]);

  return [
    ...machOHeader64(
      ncmds: 4,
      sizeofcmds:
          textCommand.length +
          dataCommand.length +
          constCommand.length +
          catlistCommand.length,
    ),
    ...textCommand,
    ...dataCommand,
    ...constCommand,
    ...catlistCommand,
    ...List.filled(paddingBeforeData, 0),
    ...namesData,
    ...propertyNameData,
    ...propertyAttributesData,
    ...classData,
    ...classRoData,
    ...categoryData,
    ...propertyListData,
    ...catlistData,
  ];
}

List<int> thinMachOWithObjCProtocolPropertyList({
  required String protocolName,
  required List<({String name, String attributes})> properties,
  bool classProperty = false,
  int paddingBeforeData = 0,
}) {
  final protocolNameAddress = 0x100000100;
  final propertyNameAddress = 0x100000500;
  final propertyAttributesAddress = 0x100000900;
  final protocolAddress = 0x100001000;
  final protocolListAddress = 0x100002000;
  final protocolNameData = cStringBytes([protocolName]);
  final propertyNameData = cStringBytes([
    for (final property in properties) property.name,
  ]);
  final propertyNameOffsets = stringOffsets([
    for (final property in properties) property.name,
  ]);
  final propertyAttributesData = cStringBytes([
    for (final property in properties) property.attributes,
  ]);
  final propertyAttributesOffsets = stringOffsets([
    for (final property in properties) property.attributes,
  ]);
  final protocolSize = classProperty ? 96 : 64;
  final propertyListAddress = protocolAddress + protocolSize;
  final propertyListData = objcPropertyList64Bytes([
    for (var i = 0; i < properties.length; i += 1)
      (
        nameAddress: propertyNameAddress + propertyNameOffsets[i],
        attributesAddress:
            propertyAttributesAddress + propertyAttributesOffsets[i],
      ),
  ]);
  final protocolData = objcProtocol64Bytes(
    protocolNameAddress,
    instancePropertiesAddress: classProperty ? 0 : propertyListAddress,
    classPropertiesAddress: classProperty ? propertyListAddress : 0,
  );
  final protocolListData = u64(protocolAddress);
  final commandsSize = (72 + 3 * 80) + 2 * (72 + 80);
  final protocolNameOffset = 32 + commandsSize + paddingBeforeData;
  final propertyNameOffset = protocolNameOffset + protocolNameData.length;
  final propertyAttributesOffset = propertyNameOffset + propertyNameData.length;
  final protocolOffset =
      propertyAttributesOffset + propertyAttributesData.length;
  final propertyListOffset = protocolOffset + protocolData.length;
  final protocolListOffset = propertyListOffset + propertyListData.length;

  final textCommand = machoSegment64AddressRangeCommand('__TEXT', [
    (
      name: '__objc_classname',
      segmentName: '__TEXT',
      address: protocolNameAddress,
      fileOffset: protocolNameOffset,
      size: protocolNameData.length,
    ),
    (
      name: '__objc_methname',
      segmentName: '__TEXT',
      address: propertyNameAddress,
      fileOffset: propertyNameOffset,
      size: propertyNameData.length,
    ),
    (
      name: '__objc_methtype',
      segmentName: '__TEXT',
      address: propertyAttributesAddress,
      fileOffset: propertyAttributesOffset,
      size: propertyAttributesData.length,
    ),
  ]);
  final constCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_const',
      segmentName: '__DATA_CONST',
      address: protocolAddress,
      fileOffset: protocolOffset,
      size: protocolData.length + propertyListData.length,
    ),
  ]);
  final protocolListCommand =
      machoSegment64AddressRangeCommand('__DATA_CONST', [
        (
          name: '__objc_protolist',
          segmentName: '__DATA_CONST',
          address: protocolListAddress,
          fileOffset: protocolListOffset,
          size: protocolListData.length,
        ),
      ]);

  return [
    ...machOHeader64(
      ncmds: 3,
      sizeofcmds:
          textCommand.length + constCommand.length + protocolListCommand.length,
    ),
    ...textCommand,
    ...constCommand,
    ...protocolListCommand,
    ...List.filled(paddingBeforeData, 0),
    ...protocolNameData,
    ...propertyNameData,
    ...propertyAttributesData,
    ...protocolData,
    ...propertyListData,
    ...protocolListData,
  ];
}

List<int> thinMachOWithObjCInheritedProtocolPropertyList({
  required String protocolName,
  required String inheritedProtocolName,
  required List<({String name, String attributes})> inheritedProperties,
  int paddingBeforeData = 0,
}) {
  final protocolNameAddress = 0x100000100;
  final propertyNameAddress = 0x100000500;
  final propertyAttributesAddress = 0x100000900;
  final protocolAddress = 0x100001000;
  final inheritedProtocolAddress = protocolAddress + 64;
  final inheritedProtocolListAddress = inheritedProtocolAddress + 64;
  final topLevelProtocolListAddress = 0x100002000;
  final protocolNamesData = cStringBytes([protocolName, inheritedProtocolName]);
  final protocolNameOffsets = stringOffsets([
    protocolName,
    inheritedProtocolName,
  ]);
  final propertyNameData = cStringBytes([
    for (final property in inheritedProperties) property.name,
  ]);
  final propertyNameOffsets = stringOffsets([
    for (final property in inheritedProperties) property.name,
  ]);
  final propertyAttributesData = cStringBytes([
    for (final property in inheritedProperties) property.attributes,
  ]);
  final propertyAttributesOffsets = stringOffsets([
    for (final property in inheritedProperties) property.attributes,
  ]);
  final inheritedProtocolListData = objcProtocolList64Bytes([
    inheritedProtocolAddress,
  ]);
  final propertyListAddress =
      inheritedProtocolListAddress + inheritedProtocolListData.length;
  final propertyListData = objcPropertyList64Bytes([
    for (var i = 0; i < inheritedProperties.length; i += 1)
      (
        nameAddress: propertyNameAddress + propertyNameOffsets[i],
        attributesAddress:
            propertyAttributesAddress + propertyAttributesOffsets[i],
      ),
  ]);
  final protocolData = [
    ...objcProtocol64Bytes(
      protocolNameAddress + protocolNameOffsets[0],
      protocolsAddress: inheritedProtocolListAddress,
    ),
    ...objcProtocol64Bytes(
      protocolNameAddress + protocolNameOffsets[1],
      instancePropertiesAddress: propertyListAddress,
    ),
    ...inheritedProtocolListData,
    ...propertyListData,
  ];
  final topLevelProtocolListData = u64(protocolAddress);
  final commandsSize = (72 + 3 * 80) + 2 * (72 + 80);
  final protocolNameOffset = 32 + commandsSize + paddingBeforeData;
  final propertyNameOffset = protocolNameOffset + protocolNamesData.length;
  final propertyAttributesOffset = propertyNameOffset + propertyNameData.length;
  final protocolOffset =
      propertyAttributesOffset + propertyAttributesData.length;
  final topLevelProtocolListOffset = protocolOffset + protocolData.length;

  final textCommand = machoSegment64AddressRangeCommand('__TEXT', [
    (
      name: '__objc_classname',
      segmentName: '__TEXT',
      address: protocolNameAddress,
      fileOffset: protocolNameOffset,
      size: protocolNamesData.length,
    ),
    (
      name: '__objc_methname',
      segmentName: '__TEXT',
      address: propertyNameAddress,
      fileOffset: propertyNameOffset,
      size: propertyNameData.length,
    ),
    (
      name: '__objc_methtype',
      segmentName: '__TEXT',
      address: propertyAttributesAddress,
      fileOffset: propertyAttributesOffset,
      size: propertyAttributesData.length,
    ),
  ]);
  final constCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_const',
      segmentName: '__DATA_CONST',
      address: protocolAddress,
      fileOffset: protocolOffset,
      size: protocolData.length,
    ),
  ]);
  final protocolListCommand =
      machoSegment64AddressRangeCommand('__DATA_CONST', [
        (
          name: '__objc_protolist',
          segmentName: '__DATA_CONST',
          address: topLevelProtocolListAddress,
          fileOffset: topLevelProtocolListOffset,
          size: topLevelProtocolListData.length,
        ),
      ]);

  return [
    ...machOHeader64(
      ncmds: 3,
      sizeofcmds:
          textCommand.length + constCommand.length + protocolListCommand.length,
    ),
    ...textCommand,
    ...constCommand,
    ...protocolListCommand,
    ...List.filled(paddingBeforeData, 0),
    ...protocolNamesData,
    ...propertyNameData,
    ...propertyAttributesData,
    ...protocolData,
    ...topLevelProtocolListData,
  ];
}

List<int> thinMachOWithObjCClassProtocolPropertyList({
  required String className,
  required String protocolName,
  required List<({String name, String attributes})> properties,
  int paddingBeforeData = 0,
}) {
  final classNameAddress = 0x100000100;
  final protocolAndPropertyNameAddress = 0x100000500;
  final propertyAttributesAddress = 0x100000900;
  final classAddress = 0x100001000;
  final classRoAddress = 0x100001800;
  final classListAddress = 0x100003000;
  final classNameData = cStringBytes([className]);
  final protocolAndPropertyNameData = cStringBytes([
    protocolName,
    for (final property in properties) property.name,
  ]);
  final protocolAndPropertyNameOffsets = stringOffsets([
    protocolName,
    for (final property in properties) property.name,
  ]);
  final propertyAttributesData = cStringBytes([
    for (final property in properties) property.attributes,
  ]);
  final propertyAttributesOffsets = stringOffsets([
    for (final property in properties) property.attributes,
  ]);
  final classData = objcClass64Bytes(classRoAddress);
  final classRoLength = objcClassRo64Bytes(
    classNameAddress,
    baseProtocolsAddress: 1,
  ).length;
  final protocolAddress = classRoAddress + classRoLength;
  final propertyListAddress = protocolAddress + 64;
  final propertyListData = objcPropertyList64Bytes([
    for (var i = 0; i < properties.length; i += 1)
      (
        nameAddress:
            protocolAndPropertyNameAddress +
            protocolAndPropertyNameOffsets[i + 1],
        attributesAddress:
            propertyAttributesAddress + propertyAttributesOffsets[i],
      ),
  ]);
  final protocolListAddress = propertyListAddress + propertyListData.length;
  final classRoData = objcClassRo64Bytes(
    classNameAddress,
    baseProtocolsAddress: protocolListAddress,
  );
  final protocolData = objcProtocol64Bytes(
    protocolAndPropertyNameAddress + protocolAndPropertyNameOffsets.first,
    instancePropertiesAddress: propertyListAddress,
  );
  final protocolListData = objcProtocolList64Bytes([protocolAddress]);
  final classListData = u64(classAddress);
  final commandsSize = (72 + 3 * 80) + 3 * (72 + 80);
  final classNameOffset = 32 + commandsSize + paddingBeforeData;
  final protocolAndPropertyNameOffset = classNameOffset + classNameData.length;
  final propertyAttributesOffset =
      protocolAndPropertyNameOffset + protocolAndPropertyNameData.length;
  final classOffset = propertyAttributesOffset + propertyAttributesData.length;
  final classRoOffset = classOffset + classData.length;
  final classListOffset =
      classRoOffset +
      classRoData.length +
      protocolData.length +
      propertyListData.length +
      protocolListData.length;

  final textCommand = machoSegment64AddressRangeCommand('__TEXT', [
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
      address: protocolAndPropertyNameAddress,
      fileOffset: protocolAndPropertyNameOffset,
      size: protocolAndPropertyNameData.length,
    ),
    (
      name: '__objc_methtype',
      segmentName: '__TEXT',
      address: propertyAttributesAddress,
      fileOffset: propertyAttributesOffset,
      size: propertyAttributesData.length,
    ),
  ]);
  final dataCommand = machoSegment64AddressRangeCommand('__DATA', [
    (
      name: '__objc_data',
      segmentName: '__DATA',
      address: classAddress,
      fileOffset: classOffset,
      size: classData.length,
    ),
  ]);
  final constCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_const',
      segmentName: '__DATA_CONST',
      address: classRoAddress,
      fileOffset: classRoOffset,
      size:
          classRoData.length +
          protocolData.length +
          propertyListData.length +
          protocolListData.length,
    ),
  ]);
  final classListCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_classlist',
      segmentName: '__DATA_CONST',
      address: classListAddress,
      fileOffset: classListOffset,
      size: classListData.length,
    ),
  ]);

  return [
    ...machOHeader64(
      ncmds: 4,
      sizeofcmds:
          textCommand.length +
          dataCommand.length +
          constCommand.length +
          classListCommand.length,
    ),
    ...textCommand,
    ...dataCommand,
    ...constCommand,
    ...classListCommand,
    ...List.filled(paddingBeforeData, 0),
    ...classNameData,
    ...protocolAndPropertyNameData,
    ...propertyAttributesData,
    ...classData,
    ...classRoData,
    ...protocolData,
    ...propertyListData,
    ...protocolListData,
    ...classListData,
  ];
}

List<int> thinMachOWithObjCMetaclassPropertyList({
  required String className,
  required List<({String name, String attributes})> properties,
  int paddingBeforeData = 0,
}) {
  final classNameAddress = 0x100000100;
  final propertyNameAddress = 0x100000500;
  final propertyAttributesAddress = 0x100000900;
  final classAddress = 0x100001000;
  final metaclassAddress = classAddress + 40;
  final classRoAddress = 0x100001800;
  final classListAddress = 0x100002800;
  final classNameData = cStringBytes([className]);
  final propertyNameData = cStringBytes([
    for (final property in properties) property.name,
  ]);
  final propertyNameOffsets = stringOffsets([
    for (final property in properties) property.name,
  ]);
  final propertyAttributesData = cStringBytes([
    for (final property in properties) property.attributes,
  ]);
  final propertyAttributesOffsets = stringOffsets([
    for (final property in properties) property.attributes,
  ]);
  final classData = objcClass64Bytes(
    classRoAddress,
    isaAddress: metaclassAddress,
  );
  final metaclassRoAddress =
      classRoAddress + objcClassRo64Bytes(classNameAddress).length;
  final propertyListAddress = metaclassRoAddress + 72;
  final propertyListData = objcPropertyList64Bytes([
    for (var i = 0; i < properties.length; i += 1)
      (
        nameAddress: propertyNameAddress + propertyNameOffsets[i],
        attributesAddress:
            propertyAttributesAddress + propertyAttributesOffsets[i],
      ),
  ]);
  final classRoData = objcClassRo64Bytes(classNameAddress);
  final metaclassData = objcClass64Bytes(metaclassRoAddress);
  final metaclassRoData = objcClassRo64Bytes(
    classNameAddress,
    basePropertiesAddress: propertyListAddress,
  );
  final classListData = u64(classAddress);
  final commandsSize = (72 + 3 * 80) + 3 * (72 + 80);
  final classNameOffset = 32 + commandsSize + paddingBeforeData;
  final propertyNameOffset = classNameOffset + classNameData.length;
  final propertyAttributesOffset = propertyNameOffset + propertyNameData.length;
  final classOffset = propertyAttributesOffset + propertyAttributesData.length;
  final classRoOffset = classOffset + classData.length + metaclassData.length;
  final classListOffset =
      classRoOffset +
      classRoData.length +
      metaclassRoData.length +
      propertyListData.length;

  final textCommand = machoSegment64AddressRangeCommand('__TEXT', [
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
      address: propertyNameAddress,
      fileOffset: propertyNameOffset,
      size: propertyNameData.length,
    ),
    (
      name: '__objc_methtype',
      segmentName: '__TEXT',
      address: propertyAttributesAddress,
      fileOffset: propertyAttributesOffset,
      size: propertyAttributesData.length,
    ),
  ]);
  final dataCommand = machoSegment64AddressRangeCommand('__DATA', [
    (
      name: '__objc_data',
      segmentName: '__DATA',
      address: classAddress,
      fileOffset: classOffset,
      size: classData.length + metaclassData.length,
    ),
  ]);
  final constCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_const',
      segmentName: '__DATA_CONST',
      address: classRoAddress,
      fileOffset: classRoOffset,
      size:
          classRoData.length + metaclassRoData.length + propertyListData.length,
    ),
  ]);
  final listCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_classlist',
      segmentName: '__DATA_CONST',
      address: classListAddress,
      fileOffset: classListOffset,
      size: classListData.length,
    ),
  ]);

  return [
    ...machOHeader64(
      ncmds: 4,
      sizeofcmds:
          textCommand.length +
          dataCommand.length +
          constCommand.length +
          listCommand.length,
    ),
    ...textCommand,
    ...dataCommand,
    ...constCommand,
    ...listCommand,
    ...List.filled(paddingBeforeData, 0),
    ...classNameData,
    ...propertyNameData,
    ...propertyAttributesData,
    ...classData,
    ...metaclassData,
    ...classRoData,
    ...metaclassRoData,
    ...propertyListData,
    ...classListData,
  ];
}

List<int> thinMachOWithObjCMetaclassMethodList({
  required String className,
  required List<String> methodNames,
  int paddingBeforeData = 0,
}) {
  final classNameAddress = 0x100000100;
  final methodNameAddress = 0x100000500;
  final classAddress = 0x100001000;
  final metaclassAddress = classAddress + 40;
  final classRoAddress = 0x100001800;
  final classListAddress = 0x100002800;
  final classNameData = cStringBytes([className]);
  final methodNameData = cStringBytes(methodNames);
  final methodNameOffsets = stringOffsets(methodNames);
  final classData = objcClass64Bytes(
    classRoAddress,
    isaAddress: metaclassAddress,
  );
  final metaclassRoAddress =
      classRoAddress + objcClassRo64Bytes(classNameAddress).length;
  final methodListAddress = metaclassRoAddress + 40;
  final methodListData = objcMethodList64Bytes([
    for (final methodNameOffset in methodNameOffsets)
      methodNameAddress + methodNameOffset,
  ]);
  final classRoData = objcClassRo64Bytes(classNameAddress);
  final metaclassData = objcClass64Bytes(metaclassRoAddress);
  final metaclassRoData = objcClassRo64Bytes(
    classNameAddress,
    baseMethodsAddress: methodListAddress,
  );
  final classListData = u64(classAddress);
  final commandsSize = (72 + 2 * 80) + 3 * (72 + 80);
  final classNameOffset = 32 + commandsSize + paddingBeforeData;
  final methodNameOffset = classNameOffset + classNameData.length;
  final classOffset = methodNameOffset + methodNameData.length;
  final classRoOffset = classOffset + classData.length + metaclassData.length;
  final classListOffset =
      classRoOffset +
      classRoData.length +
      metaclassRoData.length +
      methodListData.length;

  final textCommand = machoSegment64AddressRangeCommand('__TEXT', [
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
  final dataCommand = machoSegment64AddressRangeCommand('__DATA', [
    (
      name: '__objc_data',
      segmentName: '__DATA',
      address: classAddress,
      fileOffset: classOffset,
      size: classData.length + metaclassData.length,
    ),
  ]);
  final constCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_const',
      segmentName: '__DATA_CONST',
      address: classRoAddress,
      fileOffset: classRoOffset,
      size: classRoData.length + metaclassRoData.length + methodListData.length,
    ),
  ]);
  final listCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_classlist',
      segmentName: '__DATA_CONST',
      address: classListAddress,
      fileOffset: classListOffset,
      size: classListData.length,
    ),
  ]);

  return [
    ...machOHeader64(
      ncmds: 4,
      sizeofcmds:
          textCommand.length +
          dataCommand.length +
          constCommand.length +
          listCommand.length,
    ),
    ...textCommand,
    ...dataCommand,
    ...constCommand,
    ...listCommand,
    ...List.filled(paddingBeforeData, 0),
    ...classNameData,
    ...methodNameData,
    ...classData,
    ...metaclassData,
    ...classRoData,
    ...metaclassRoData,
    ...methodListData,
    ...classListData,
  ];
}

List<int> thinMachOWithObjCSmallMethodList({
  required String className,
  required List<String> methodNames,
  int paddingBeforeData = 0,
}) {
  final classNameAddress = 0x100000100;
  final methodNameAddress = 0x100000400;
  final classAddress = 0x100000800;
  final classRoAddress = 0x100001000;
  final selectorRefAddress = 0x100001500;
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
  final selectorRefData = [
    for (final methodNameOffset in methodNameOffsets)
      ...u64(methodNameAddress + methodNameOffset),
  ];
  final methodListData = objcSmallMethodList64Bytes(
    methodListAddress: methodListAddress,
    selectorRefAddresses: [
      for (var i = 0; i < methodNames.length; i += 1)
        selectorRefAddress + i * 8,
    ],
  );
  final classListData = u64(classAddress);
  final commandsSize = 2 * (72 + 2 * 80) + 2 * (72 + 80);
  final classNameOffset = 32 + commandsSize + paddingBeforeData;
  final methodNameOffset = classNameOffset + classNameData.length;
  final classOffset = methodNameOffset + methodNameData.length;
  final classRoOffset = classOffset + classData.length;
  final methodListOffset = classRoOffset + classRoData.length;
  final selectorRefOffset = methodListOffset + methodListData.length;
  final classListOffset = selectorRefOffset + selectorRefData.length;

  final textCommand = machoSegment64AddressRangeCommand('__TEXT', [
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
  final dataCommand = machoSegment64AddressRangeCommand('__DATA', [
    (
      name: '__objc_data',
      segmentName: '__DATA',
      address: classAddress,
      fileOffset: classOffset,
      size: classData.length,
    ),
  ]);
  final constCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_const',
      segmentName: '__DATA_CONST',
      address: classRoAddress,
      fileOffset: classRoOffset,
      size: classRoData.length + methodListData.length,
    ),
    (
      name: '__objc_selrefs',
      segmentName: '__DATA_CONST',
      address: selectorRefAddress,
      fileOffset: selectorRefOffset,
      size: selectorRefData.length,
    ),
  ]);
  final listCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_classlist',
      segmentName: '__DATA_CONST',
      address: classListAddress,
      fileOffset: classListOffset,
      size: classListData.length,
    ),
  ]);

  return [
    ...machOHeader64(
      ncmds: 4,
      sizeofcmds:
          textCommand.length +
          dataCommand.length +
          constCommand.length +
          listCommand.length,
    ),
    ...textCommand,
    ...dataCommand,
    ...constCommand,
    ...listCommand,
    ...List.filled(paddingBeforeData, 0),
    ...classNameData,
    ...methodNameData,
    ...classData,
    ...classRoData,
    ...methodListData,
    ...selectorRefData,
    ...classListData,
  ];
}

List<int> thinMachOWithObjCCategoryMethodList({
  required String className,
  required String categoryName,
  required List<String> instanceMethodNames,
  required List<String> classMethodNames,
  int paddingBeforeData = 0,
}) {
  final classNameAddress = 0x100000100;
  final methodNameAddress = 0x100000500;
  final classAddress = 0x100000800;
  final classRoAddress = 0x100001000;
  final catlistAddress = 0x100001800;
  final namesData = cStringBytes([className, categoryName]);
  final nameOffsets = stringOffsets([className, categoryName]);
  final methodNames = [...instanceMethodNames, ...classMethodNames];
  final methodNameData = cStringBytes(methodNames);
  final methodNameOffsets = stringOffsets(methodNames);
  final categoryNameAddress = classNameAddress + nameOffsets[1];
  final categoryAddress = classRoAddress + 40;
  final instanceMethodListAddress = categoryAddress + 48;
  final instanceMethodListData = objcMethodList64Bytes([
    for (var i = 0; i < instanceMethodNames.length; i += 1)
      methodNameAddress + methodNameOffsets[i],
  ]);
  final classMethodListAddress =
      instanceMethodListAddress + instanceMethodListData.length;
  final classMethodListData = objcMethodList64Bytes([
    for (var i = 0; i < classMethodNames.length; i += 1)
      methodNameAddress + methodNameOffsets[instanceMethodNames.length + i],
  ]);
  final classData = objcClass64Bytes(classRoAddress);
  final classRoData = objcClassRo64Bytes(classNameAddress);
  final categoryData = objcCategory64Bytes(
    nameAddress: categoryNameAddress,
    classAddress: classAddress,
    instanceMethodsAddress: instanceMethodNames.isEmpty
        ? 0
        : instanceMethodListAddress,
    classMethodsAddress: classMethodNames.isEmpty ? 0 : classMethodListAddress,
  );
  final catlistData = u64(categoryAddress);
  final commandsSize = (72 + 2 * 80) + 3 * (72 + 80);
  final classNameOffset = 32 + commandsSize + paddingBeforeData;
  final methodNameOffset = classNameOffset + namesData.length;
  final classOffset = methodNameOffset + methodNameData.length;
  final classRoOffset = classOffset + classData.length;
  final categoryOffset = classRoOffset + classRoData.length;
  final instanceMethodListOffset = categoryOffset + categoryData.length;
  final classMethodListOffset =
      instanceMethodListOffset + instanceMethodListData.length;
  final catlistOffset = classMethodListOffset + classMethodListData.length;

  final textCommand = machoSegment64AddressRangeCommand('__TEXT', [
    (
      name: '__objc_classname',
      segmentName: '__TEXT',
      address: classNameAddress,
      fileOffset: classNameOffset,
      size: namesData.length,
    ),
    (
      name: '__objc_methname',
      segmentName: '__TEXT',
      address: methodNameAddress,
      fileOffset: methodNameOffset,
      size: methodNameData.length,
    ),
  ]);
  final dataCommand = machoSegment64AddressRangeCommand('__DATA', [
    (
      name: '__objc_data',
      segmentName: '__DATA',
      address: classAddress,
      fileOffset: classOffset,
      size: classData.length,
    ),
  ]);
  final constCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_const',
      segmentName: '__DATA_CONST',
      address: classRoAddress,
      fileOffset: classRoOffset,
      size:
          classRoData.length +
          categoryData.length +
          instanceMethodListData.length +
          classMethodListData.length,
    ),
  ]);
  final catlistCommand = machoSegment64AddressRangeCommand('__DATA_CONST', [
    (
      name: '__objc_catlist',
      segmentName: '__DATA_CONST',
      address: catlistAddress,
      fileOffset: catlistOffset,
      size: catlistData.length,
    ),
  ]);

  return [
    ...machOHeader64(
      ncmds: 4,
      sizeofcmds:
          textCommand.length +
          dataCommand.length +
          constCommand.length +
          catlistCommand.length,
    ),
    ...textCommand,
    ...dataCommand,
    ...constCommand,
    ...catlistCommand,
    ...List.filled(paddingBeforeData, 0),
    ...namesData,
    ...methodNameData,
    ...classData,
    ...classRoData,
    ...categoryData,
    ...instanceMethodListData,
    ...classMethodListData,
    ...catlistData,
  ];
}

List<int> machOHeader64({
  required int ncmds,
  required int sizeofcmds,
  int cpuType = 0x0100000c,
  int cpuSubtype = 0,
}) {
  return [
    0xcf, 0xfa, 0xed, 0xfe, // MH_MAGIC_64
    ...u32(cpuType),
    ...u32(cpuSubtype),
    ...u32(2), // MH_EXECUTE
    ...u32(ncmds),
    ...u32(sizeofcmds),
    ...u32(0), // flags
    ...u32(0), // reserved
  ];
}

List<int> machoSymtabCommand({
  required int symbolOffset,
  required int symbolCount,
  required int stringOffset,
  required int stringSize,
}) {
  return [
    ...u32(0x02), // LC_SYMTAB
    ...u32(24),
    ...u32(symbolOffset),
    ...u32(symbolCount),
    ...u32(stringOffset),
    ...u32(stringSize),
  ];
}

List<int> machoDynamicSymtabCommand({
  required int localSymbolIndex,
  required int localSymbolCount,
  required int externalSymbolIndex,
  required int externalSymbolCount,
  required int undefinedSymbolIndex,
  required int undefinedSymbolCount,
  required int indirectSymbolOffset,
  required int indirectSymbolCount,
}) {
  return [
    ...u32(0x0b), // LC_DYSYMTAB
    ...u32(80),
    ...u32(localSymbolIndex),
    ...u32(localSymbolCount),
    ...u32(externalSymbolIndex),
    ...u32(externalSymbolCount),
    ...u32(undefinedSymbolIndex),
    ...u32(undefinedSymbolCount),
    ...u32(0), // tocoff
    ...u32(0), // ntoc
    ...u32(0), // modtaboff
    ...u32(0), // nmodtab
    ...u32(0), // extrefsymoff
    ...u32(0), // nextrefsyms
    ...u32(indirectSymbolOffset),
    ...u32(indirectSymbolCount),
    ...u32(0), // extreloff
    ...u32(0), // nextrel
    ...u32(0), // locreloff
    ...u32(0), // nlocrel
  ];
}

List<int> machoDyldInfoCommand({
  required int bindOffset,
  required int bindSize,
  int weakBindOffset = 0,
  int weakBindSize = 0,
  int lazyBindOffset = 0,
  int lazyBindSize = 0,
  int exportOffset = 0,
  int exportSize = 0,
}) {
  return [
    ...u32(0x80000022),
    ...u32(48),
    ...u32(0),
    ...u32(0),
    ...u32(bindOffset),
    ...u32(bindSize),
    ...u32(weakBindOffset),
    ...u32(weakBindSize),
    ...u32(lazyBindOffset),
    ...u32(lazyBindSize),
    ...u32(exportOffset),
    ...u32(exportSize),
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

List<int> machoFunctionStartsCommand({
  required int dataOffset,
  required int dataSize,
}) {
  return [...u32(0x26), ...u32(16), ...u32(dataOffset), ...u32(dataSize)];
}

List<int> machoDataInCodeCommand({
  required int dataOffset,
  required int dataSize,
}) {
  return [...u32(0x29), ...u32(16), ...u32(dataOffset), ...u32(dataSize)];
}

List<int> machoLinkerOptionCommand(List<String> values) {
  final strings = [
    for (final value in values) ...[...latin1.encode(value), 0],
  ];
  final commandSize = _alignTo(12 + strings.length, 8);
  return [
    ...u32(0x2d),
    ...u32(commandSize),
    ...u32(values.length),
    ...strings,
    ...List.filled(commandSize - 12 - strings.length, 0),
  ];
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

List<int> dataInCodeBytes(List<({int offset, int length, int kind})> entries) {
  return [
    for (final entry in entries) ...[
      ...u32(entry.offset),
      ...u16(entry.length),
      ...u16(entry.kind),
    ],
  ];
}

List<int> functionStartsBytes(List<int> offsets) {
  final result = <int>[];
  var previous = 0;
  for (final offset in offsets) {
    result.addAll(uleb128(offset - previous));
    previous = offset;
  }
  result.add(0);
  return result;
}

List<int> chainedFixupsPayload(
  List<String> symbols, {
  required int importFormat,
  int symbolsFormat = 0,
  bool corruptCompressedSymbols = false,
  bool includeStartsMetadata = false,
}) {
  final symbolStrings = switch (symbolsFormat) {
    0 => cStringBytes(symbols),
    1 =>
      corruptCompressedSymbols
          ? [0x78, 0x9c, 0x01]
          : zlib.encode(cStringBytes(symbols)),
    _ => throw ArgumentError.value(symbolsFormat, 'symbolsFormat'),
  };
  final symbolOffsets = stringOffsets(symbols);
  final entrySize = switch (importFormat) {
    1 => 4,
    2 => 8,
    3 => 16,
    _ => throw ArgumentError.value(importFormat, 'importFormat'),
  };
  const headerSize = 28;
  final starts = includeStartsMetadata
      ? chainedStartsInImagePayload()
      : <int>[];
  final startsOffset = starts.isEmpty ? 0 : headerSize;
  final importsOffset = headerSize + starts.length;
  final symbolsOffset = importsOffset + entrySize * symbols.length;

  return [
    ...u32(0), // fixups_version
    ...u32(startsOffset),
    ...u32(importsOffset),
    ...u32(symbolsOffset),
    ...u32(symbols.length),
    ...u32(importFormat),
    ...u32(symbolsFormat),
    ...starts,
    for (final symbolOffset in symbolOffsets)
      ...chainedImportEntry(
        importFormat: importFormat,
        nameOffset: symbolOffset,
      ),
    ...symbolStrings,
  ];
}

List<int> chainedImportEntry({
  required int importFormat,
  required int nameOffset,
}) {
  final raw = 1 | (nameOffset << 9);
  return switch (importFormat) {
    1 => u32(raw),
    2 => [...u32(raw), ...u32(0)],
    3 => [...u64(1 | (nameOffset << 32)), ...u64(0)],
    _ => throw ArgumentError.value(importFormat, 'importFormat'),
  };
}

List<int> chainedStartsInImagePayload() {
  const pageStarts = [0x18, 0xffff];
  final segmentStarts = [
    ...u32(22 + pageStarts.length * 2),
    ...u16(0x4000),
    ...u16(9),
    ...u64(0x8000),
    ...u32(0),
    ...u16(pageStarts.length),
    for (final pageStart in pageStarts) ...u16(pageStart),
  ];

  return [...u32(1), ...u32(8), ...segmentStarts];
}

List<int> nlist64Bytes(int stringIndex) {
  return [
    ...u32(stringIndex),
    0x0f, // N_SECT | N_EXT
    0x01, // n_sect
    ...u16(0), // n_desc
    ...u64(0), // n_value
  ];
}

List<int> stringTableBytes(List<String> symbols) {
  return [
    0,
    for (final symbol in symbols) ...[...latin1.encode(symbol), 0],
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

List<int> objcClass64Bytes(
  int dataAddress, {
  int isaAddress = 0,
  int superclassAddress = 0,
}) {
  return [
    ...u64(isaAddress), // isa
    ...u64(superclassAddress), // superclass
    ...u64(0), // cache
    ...u64(0), // vtable
    ...u64(dataAddress), // class_ro_t pointer, low bits may contain flags
  ];
}

List<int> objcClassRo64Bytes(
  int nameAddress, {
  int baseMethodsAddress = 0,
  int baseProtocolsAddress = 0,
  int ivarsAddress = 0,
  int basePropertiesAddress = 0,
}) {
  final bytes = [
    ...u32(0), // flags
    ...u32(0), // instanceStart
    ...u32(0), // instanceSize
    ...u32(0), // reserved
    ...u64(0), // ivarLayout
    ...u64(nameAddress), // name
    ...u64(baseMethodsAddress),
  ];
  if (baseProtocolsAddress != 0 ||
      ivarsAddress != 0 ||
      basePropertiesAddress != 0) {
    bytes.addAll(u64(baseProtocolsAddress));
  }
  if (ivarsAddress != 0 || basePropertiesAddress != 0) {
    bytes
      ..addAll(u64(ivarsAddress))
      ..addAll(u64(0)) // weakIvarLayout
      ..addAll(u64(basePropertiesAddress));
  }
  return bytes;
}

List<int> objcCategory64Bytes({
  required int nameAddress,
  required int classAddress,
  required int instanceMethodsAddress,
  required int classMethodsAddress,
  int protocolsAddress = 0,
  int instancePropertiesAddress = 0,
  int classPropertiesAddress = 0,
}) {
  final bytes = [
    ...u64(nameAddress),
    ...u64(classAddress),
    ...u64(instanceMethodsAddress),
    ...u64(classMethodsAddress),
    ...u64(protocolsAddress),
    ...u64(instancePropertiesAddress),
  ];
  if (classPropertiesAddress != 0) {
    bytes.addAll(u64(classPropertiesAddress));
  }
  return bytes;
}

List<int> objcProtocol64Bytes(
  int nameAddress, {
  int protocolsAddress = 0,
  int instanceMethodsAddress = 0,
  int classMethodsAddress = 0,
  int optionalInstanceMethodsAddress = 0,
  int optionalClassMethodsAddress = 0,
  int instancePropertiesAddress = 0,
  int classPropertiesAddress = 0,
}) {
  final bytes = [
    ...u64(0), // isa
    ...u64(nameAddress),
    ...u64(protocolsAddress),
    ...u64(instanceMethodsAddress),
    ...u64(classMethodsAddress),
    ...u64(optionalInstanceMethodsAddress),
    ...u64(optionalClassMethodsAddress),
    ...u64(instancePropertiesAddress), // instance properties
  ];
  if (classPropertiesAddress != 0) {
    bytes
      ..addAll(u32(96)) // size
      ..addAll(u32(0)) // flags
      ..addAll(u64(0)) // extended method types
      ..addAll(u64(0)) // demangled name
      ..addAll(u64(classPropertiesAddress)); // class properties
  }
  return bytes;
}

List<int> objcProtocolList64Bytes(List<int> protocolAddresses) {
  return [
    ...u64(protocolAddresses.length),
    for (final protocolAddress in protocolAddresses) ...u64(protocolAddress),
  ];
}

List<int> objcMethodList64Bytes(List<int> methodNameAddresses) {
  return [
    ...u32(24), // entsizeAndFlags
    ...u32(methodNameAddresses.length),
    for (final methodNameAddress in methodNameAddresses) ...[
      ...u64(methodNameAddress),
      ...u64(0), // types
      ...u64(0), // imp
    ],
  ];
}

List<int> objcIvarList64Bytes(
  List<({int nameAddress, int typeAddress})> ivars,
) {
  return [
    ...u32(32), // entsize
    ...u32(ivars.length),
    for (final ivar in ivars) ...[
      ...u64(0), // offset pointer
      ...u64(ivar.nameAddress),
      ...u64(ivar.typeAddress),
      ...u32(3), // alignment
      ...u32(8), // size
    ],
  ];
}

List<int> objcPropertyList64Bytes(
  List<({int nameAddress, int attributesAddress})> properties,
) {
  return [
    ...u32(16), // entsize
    ...u32(properties.length),
    for (final property in properties) ...[
      ...u64(property.nameAddress),
      ...u64(property.attributesAddress),
    ],
  ];
}

List<int> objcSmallMethodList64Bytes({
  required int methodListAddress,
  required List<int> selectorRefAddresses,
}) {
  return [
    ...u32(0x8000000c),
    ...u32(selectorRefAddresses.length),
    for (var i = 0; i < selectorRefAddresses.length; i += 1) ...[
      ...u32(selectorRefAddresses[i] - (methodListAddress + 8 + i * 12)),
      ...u32(0),
      ...u32(0),
    ],
  ];
}

List<int> objcRelativeMethodListList64Bytes({
  required int listListAddress,
  required List<int> methodListAddresses,
}) {
  return [
    ...u32(8),
    ...u32(methodListAddresses.length),
    for (var i = 0; i < methodListAddresses.length; i += 1)
      ...u64(
        ((methodListAddresses[i] - (listListAddress + 8 + i * 8)) << 16) &
            0xffffffffffff0000,
      ),
  ];
}

List<int> machOLoadDylibCommand(
  String dylibPath, {
  bool weak = false,
  int? command,
}) {
  final pathBytes = [...latin1.encode(dylibPath), 0];
  final commandSize = 24 + pathBytes.length;
  return [
    ...u32(command ?? (weak ? 0x80000018 : 0x0c)),
    ...u32(commandSize),
    ...u32(24), // dylib.name offset
    ...u32(0), // timestamp
    ...u32(0x00010000), // current version 1.0.0
    ...u32(0x00010000), // compatibility version 1.0.0
    ...pathBytes,
  ];
}

List<int> machoBuildVersionCommand({
  required int platform,
  required int minimumOsVersion,
  required int sdkVersion,
  List<({int tool, int version})> tools = const [],
}) {
  return [
    ...u32(0x32), // LC_BUILD_VERSION
    ...u32(24 + tools.length * 8),
    ...u32(platform),
    ...u32(minimumOsVersion),
    ...u32(sdkVersion),
    ...u32(tools.length),
    for (final tool in tools) ...[...u32(tool.tool), ...u32(tool.version)],
  ];
}

List<int> machoVersionMinCommand({
  required int command,
  required int minimumOsVersion,
  required int sdkVersion,
}) {
  return [
    ...u32(command),
    ...u32(16),
    ...u32(minimumOsVersion),
    ...u32(sdkVersion),
  ];
}

List<int> machoRpathCommand(String path) => machoPathCommand(0x8000001c, path);

List<int> machoDylibIdCommand(String dylibPath) {
  final pathBytes = [...latin1.encode(dylibPath), 0];
  final commandSize = 24 + pathBytes.length;
  return [
    ...u32(0x0d), // LC_ID_DYLIB
    ...u32(commandSize),
    ...u32(24), // dylib.name offset
    ...u32(0), // timestamp
    ...u32(0x00010000), // current version 1.0.0
    ...u32(0x00010000), // compatibility version 1.0.0
    ...pathBytes,
  ];
}

List<int> machoPathCommand(int command, String path) {
  final pathBytes = [...latin1.encode(path), 0];
  final commandSize = 12 + pathBytes.length;
  return [
    ...u32(command),
    ...u32(commandSize),
    ...u32(12), // path offset
    ...pathBytes,
  ];
}

List<int> machoUuidCommand(List<int> uuid) {
  return [
    ...u32(0x1b), // LC_UUID
    ...u32(24),
    ...uuid,
  ];
}

List<int> machoSourceVersionCommand(int version) {
  return [
    ...u32(0x2a), // LC_SOURCE_VERSION
    ...u32(16),
    ...u64(version),
  ];
}

List<int> machoCodeSignatureCommand({
  required int dataOffset,
  required int dataSize,
}) {
  return [
    ...u32(0x1d), // LC_CODE_SIGNATURE
    ...u32(16),
    ...u32(dataOffset),
    ...u32(dataSize),
  ];
}

List<int> machoEncryptionInfoCommand({
  required int cryptOffset,
  required int cryptSize,
  required int cryptId,
  int command = 0x21,
}) {
  return [
    ...u32(command),
    ...u32(command == 0x2c ? 24 : 20),
    ...u32(cryptOffset),
    ...u32(cryptSize),
    ...u32(cryptId),
    if (command == 0x2c) ...u32(0),
  ];
}

List<int> machoMainCommand({required int entryOffset, required int stackSize}) {
  return [
    ...u32(0x80000028),
    ...u32(24),
    ...u64(entryOffset),
    ...u64(stackSize),
  ];
}

List<int> machoSegment64Command(
  String segmentName,
  List<({String name, String segmentName})> sections,
) {
  return machoSegment64RangeCommand(segmentName, [
    for (final section in sections)
      (
        name: section.name,
        segmentName: section.segmentName,
        fileOffset: 0,
        size: 0,
      ),
  ]);
}

List<int> machoSegment64RangeCommand(
  String segmentName,
  List<({String name, String segmentName, int fileOffset, int size})> sections,
) {
  return machoSegment64AddressRangeCommand(segmentName, [
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

List<int> machoSegment64AddressRangeCommand(
  String segmentName,
  List<
    ({String name, String segmentName, int address, int fileOffset, int size})
  >
  sections,
) {
  return [
    ...u32(0x19), // LC_SEGMENT_64
    ...u32(72 + sections.length * 80),
    ...fixedString(segmentName, 16),
    ...u64(0), // vmaddr
    ...u64(0), // vmsize
    ...u64(0), // fileoff
    ...u64(0), // filesize
    ...u32(0), // maxprot
    ...u32(0), // initprot
    ...u32(sections.length),
    ...u32(0), // flags
    for (final section in sections) ...section64Bytes(section),
  ];
}

List<int> section64Bytes(
  ({String name, String segmentName, int address, int fileOffset, int size})
  section,
) {
  return [
    ...fixedString(section.name, 16),
    ...fixedString(section.segmentName, 16),
    ...u64(section.address),
    ...u64(section.size),
    ...u32(section.fileOffset),
    ...u32(0), // align
    ...u32(0), // reloff
    ...u32(0), // nreloc
    ...u32(0), // flags
    ...u32(0), // reserved1
    ...u32(0), // reserved2
    ...u32(0), // reserved3
  ];
}

List<int> fatMachO(List<List<int>> slices, {bool fat64 = false}) {
  const headerSize = 8;
  final archSize = fat64 ? 32 : 20;
  var nextOffset = headerSize + archSize * slices.length;
  final archHeaders = <int>[];
  final payload = <int>[];

  for (final slice in slices) {
    archHeaders
      ..addAll(u32be(0x0100000c)) // CPU_TYPE_ARM64
      ..addAll(u32be(0)); // CPU_SUBTYPE_ARM64_ALL
    if (fat64) {
      archHeaders
        ..addAll(u64be(nextOffset))
        ..addAll(u64be(slice.length))
        ..addAll(u32be(0)) // align
        ..addAll(u32be(0)); // reserved
    } else {
      archHeaders
        ..addAll(u32be(nextOffset))
        ..addAll(u32be(slice.length))
        ..addAll(u32be(0)); // align
    }
    payload.addAll(slice);
    nextOffset += slice.length;
  }

  return [
    ...u32be(fat64 ? 0xcafebabf : 0xcafebabe),
    ...u32be(slices.length),
    ...archHeaders,
    ...payload,
  ];
}

int sourceVersion(int a, int b, int c, int d, int e) {
  return (a << 40) | (b << 30) | (c << 20) | (d << 10) | e;
}

int _alignTo(int value, int alignment) {
  final remainder = value % alignment;
  return remainder == 0 ? value : value + alignment - remainder;
}

List<int> fixedString(String value, int length) {
  final bytes = latin1.encode(value);
  return [
    ...bytes.take(length),
    ...List.filled(length - (bytes.length > length ? length : bytes.length), 0),
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

List<int> u64be(int value) {
  return [
    (value >> 56) & 0xff,
    (value >> 48) & 0xff,
    (value >> 40) & 0xff,
    (value >> 32) & 0xff,
    (value >> 24) & 0xff,
    (value >> 16) & 0xff,
    (value >> 8) & 0xff,
    value & 0xff,
  ];
}
