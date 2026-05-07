import 'dart:convert';

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
}) {
  return [
    ...u32(0x32), // LC_BUILD_VERSION
    ...u32(24),
    ...u32(platform),
    ...u32(minimumOsVersion),
    ...u32(sdkVersion),
    ...u32(0), // ntools
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
