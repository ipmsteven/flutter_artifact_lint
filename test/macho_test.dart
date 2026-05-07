import 'dart:convert';

import 'package:flutter_artifact_lint/src/macho.dart';
import 'package:test/test.dart';

void main() {
  group('MachOParser', () {
    test('reads strong and weak linked dylib load commands', () {
      final report = const MachOParser().parse([
        ...machOHeader64(ncmds: 2),
        ...machOLoadDylibCommand(
          '/System/Library/Frameworks/Contacts.framework/Contacts',
        ),
        ...machOLoadDylibCommand(
          '/System/Library/Frameworks/CoreLocation.framework/CoreLocation',
          weak: true,
        ),
      ]);

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

    test('ignores non-Mach-O bytes', () {
      final report = const MachOParser().parse(latin1.encode('not a binary'));

      expect(report.linkedDylibs, isEmpty);
    });

    test('stops on malformed load command sizes', () {
      final report = const MachOParser().parse([
        ...machOHeader64(ncmds: 1),
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

List<int> machOHeader64({required int ncmds}) {
  return [
    0xcf, 0xfa, 0xed, 0xfe, // MH_MAGIC_64
    ...u32(0x0100000c), // CPU_TYPE_ARM64
    ...u32(0), // CPU_SUBTYPE_ARM64_ALL
    ...u32(2), // MH_EXECUTE
    ...u32(ncmds),
    ...u32(0), // sizeofcmds is not needed by these tests
    ...u32(0), // flags
    ...u32(0), // reserved
  ];
}

List<int> machOLoadDylibCommand(String dylibPath, {bool weak = false}) {
  final pathBytes = [...latin1.encode(dylibPath), 0];
  final commandSize = 24 + pathBytes.length;
  return [
    ...u32(weak ? 0x80000018 : 0x0c),
    ...u32(commandSize),
    ...u32(24), // dylib.name offset
    ...u32(0), // timestamp
    ...u32(0x00010000), // current version 1.0.0
    ...u32(0x00010000), // compatibility version 1.0.0
    ...pathBytes,
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
