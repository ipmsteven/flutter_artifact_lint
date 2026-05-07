import 'dart:io';

import 'package:flutter_artifact_lint/src/plist.dart';
import 'package:test/test.dart';

void main() {
  test(
    'parses binary plist files produced by Xcode',
    () {
      final tempDir = Directory.systemTemp.createTempSync('fal_plist_');
      addTearDown(() => tempDir.deleteSync(recursive: true));

      final plist = File('${tempDir.path}/Info.plist')
        ..writeAsStringSync('''
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>com.example.runner</string>
</dict>
</plist>
''');

      final convert = Process.runSync('plutil', [
        '-convert',
        'binary1',
        plist.path,
      ]);
      expect(
        convert.exitCode,
        0,
        reason: '${convert.stdout}\n${convert.stderr}',
      );

      final parsed = parsePlistFile(plist.path);

      expect(parsed['CFBundleIdentifier'], 'com.example.runner');
    },
    skip: !Platform.isMacOS ? 'Binary plist parsing uses macOS plutil.' : false,
  );
}
