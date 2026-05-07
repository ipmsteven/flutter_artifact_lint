import 'dart:io';

import 'package:flutter_artifact_lint/src/macho.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

void main() {
  test(
    'parses Objective-C metadata from a real clang Mach-O binary',
    () async {
      if (!Platform.isMacOS) {
        print('Skipping: Objective-C Mach-O builds require macOS.');
        return;
      }
      if (!_commandExists('xcrun')) {
        print('Skipping: xcrun is not available on PATH.');
        return;
      }

      final clang = await Process.run('xcrun', ['--find', 'clang']);
      if (clang.exitCode != 0) {
        print('Skipping: clang is not available through xcrun.');
        return;
      }

      final tempDir = await Directory.systemTemp.createTemp(
        'fal_objc_macho_e2e_',
      );
      addTearDown(() => tempDir.delete(recursive: true));

      final source = File(p.join(tempDir.path, 'main.m'))
        ..writeAsStringSync('''
@protocol FlutterPlugin
- (void)registerWithRegistrar:(id)registrar;
@end

__attribute__((objc_root_class))
@interface RunnerViewController <FlutterPlugin>
- (void)requestWhenInUseAuthorization;
@end

@implementation RunnerViewController
- (void)requestWhenInUseAuthorization {}
- (void)registerWithRegistrar:(id)registrar {}
@end

int main(void) { return 0; }
''');
      final binary = File(p.join(tempDir.path, 'ObjCFixture'));
      final build = await Process.run('xcrun', [
        'clang',
        '-x',
        'objective-c',
        source.path,
        '-lobjc',
        '-o',
        binary.path,
      ]).timeout(const Duration(minutes: 2));
      expect(
        build.exitCode,
        0,
        reason: 'clang failed\n${build.stdout}\n${build.stderr}',
      );

      final report = const MachOParser().parseFile(binary);

      expect(
        report.objcClasses.map((objcClass) => objcClass.name),
        contains('RunnerViewController'),
      );
      expect(
        report.objcProtocols.map((protocol) => protocol.name),
        contains('FlutterPlugin'),
      );
      expect(
        report.objcMethods.map((method) => method.name),
        containsAll([
          'requestWhenInUseAuthorization',
          'registerWithRegistrar:',
        ]),
      );
      expect(
        report.objcSelectors.map((selector) => selector.name),
        containsAll([
          'requestWhenInUseAuthorization',
          'registerWithRegistrar:',
        ]),
      );
    },
    timeout: const Timeout(Duration(minutes: 3)),
  );
}

bool _commandExists(String command) {
  final result = Process.runSync('which', [command]);
  return result.exitCode == 0;
}
