import 'dart:io';

import 'package:flutter_artifact_lint/src/ios_artifact_scanner.dart';
import 'package:flutter_artifact_lint/src/model.dart';
import 'package:test/test.dart';

void main() {
  test(
    'reports deterministic failed rules from the final Info.plist and manifests',
    () async {
      final fixture = await AppFixture.create();
      addTearDown(fixture.delete);

      fixture.writeInfoPlist({
        'NSCameraUsageDescription': 'TODO',
        'NSMicrophoneUsageDescription': '',
        'NSPhotoLibraryUsageDescription': 'placeholder',
        'NSContactsUsageDescription': 'add description',
        'NSBluetoothAlwaysUsageDescription': 'FIXME',
        'NSFaceIDUsageDescription': 'description here',
        'NSLocationAlwaysAndWhenInUseUsageDescription':
            'Track routes in the background.',
        'NSAppTransportSecurity': {'NSAllowsArbitraryLoads': true},
      });
      fixture.writeFile('PrivacyInfo.xcprivacy', 'not a plist');

      final result = await IosArtifactScanner().scan(fixture.appPath);

      expectRule(result.failed, 'ios.permission.camera.empty');
      expectRule(result.failed, 'ios.permission.microphone.empty');
      expectRule(result.failed, 'ios.permission.photos.empty');
      expectRule(result.failed, 'ios.permission.contacts.empty');
      expectRule(result.failed, 'ios.permission.bluetooth.empty');
      expectRule(result.failed, 'ios.permission.face_id.empty');
      expectRule(result.failed, 'ios.export_compliance.missing');
      expectRule(result.failed, 'ios.launch_screen.missing');
      expectRule(result.failed, 'ios.orientations.missing');
      expectRule(result.failed, 'ios.ats.arbitrary_loads');
      expectRule(result.failed, 'ios.location.always_without_background_mode');
      expectRule(result.failed, 'ios.privacy_manifest.invalid');
    },
  );

  test('reports missing permission warnings from binary evidence', () async {
    final fixture = await AppFixture.create();
    addTearDown(fixture.delete);

    fixture.writeInfoPlist(_validBasePlist());
    fixture.writeFramework('Contacts.framework', 'CNContactStore');
    fixture.writeFramework('CameraKit.framework', 'AVCaptureSession');
    fixture.writeFramework('AudioKit.framework', 'AVAudioRecorder');
    fixture.writeFramework(
      'LocationKit.framework',
      'CLLocationManager requestWhenInUseAuthorization',
    );
    fixture.writeFramework(
      'Photos.framework',
      'PHPhotoLibrary PHPickerViewController',
    );
    fixture.writeFramework('CoreBluetooth.framework', 'CBCentralManager');
    fixture.writeFramework('LocalAuthentication.framework', 'LAContext');
    fixture.writeFramework(
      'UserNotifications.framework',
      'UNUserNotificationCenter requestAuthorization',
    );

    final result = await IosArtifactScanner().scan(fixture.appPath);

    expectRule(result.warned, 'ios.permission.contacts.missing');
    expectRule(result.warned, 'ios.permission.camera.missing');
    expectRule(result.warned, 'ios.permission.microphone.missing');
    expectRule(result.warned, 'ios.permission.location.missing');
    expectRule(result.warned, 'ios.permission.photos.missing');
    expectRule(result.warned, 'ios.permission.bluetooth.missing');
    expectRule(result.warned, 'ios.permission.face_id.missing');
    expectRule(result.warned, 'ios.notification.evidence');
  });

  test(
    'reports required reason API evidence and privacy manifest declaration issues',
    () async {
      final fixture = await AppFixture.create();
      addTearDown(fixture.delete);

      fixture.writeInfoPlist(_validBasePlist());
      fixture.writeFile(
        'Frameworks/Storage.framework/Storage',
        'UserDefaults statfs systemUptime activeInputModes NSFileModificationDate',
      );
      fixture.writePrivacyManifest([
        {
          'NSPrivacyAccessedAPIType':
              'NSPrivacyAccessedAPICategoryUserDefaults',
          'NSPrivacyAccessedAPITypeReasons': <String>[],
        },
      ]);

      final result = await IosArtifactScanner().scan(fixture.appPath);

      expectRule(result.failed, 'ios.privacy_manifest.empty_reasons');
      expectRule(result.warned, 'ios.required_reason.file_timestamp');
      expectRule(result.warned, 'ios.required_reason.disk_space');
      expectRule(result.warned, 'ios.required_reason.system_boot_time');
      expectRule(result.warned, 'ios.required_reason.active_keyboards');
    },
  );

  test('reports private API and dynamic code evidence as warnings', () async {
    final fixture = await AppFixture.create();
    addTearDown(fixture.delete);

    fixture.writeInfoPlist(_validBasePlist());
    fixture.writeFile(
      'Frameworks/Risky.framework/Risky',
      'UIWebView _UIApplicationOpenSettingsURLString dlopen dlsym JSContext evaluateScript',
    );

    final result = await IosArtifactScanner().scan(fixture.appPath);

    expectRule(result.warned, 'ios.private_api.uiwebview');
    expectRule(result.warned, 'ios.private_api.selector');
    expectRule(result.warned, 'ios.dynamic_code_execution.evidence');
  });

  test(
    'reports placeholder purpose strings in nested app extensions',
    () async {
      final fixture = await AppFixture.create();
      addTearDown(fixture.delete);

      fixture.writeInfoPlist(_validBasePlist());
      fixture.writeFile(
        'PlugIns/ShareExtension.appex/Info.plist',
        _plist({
          'CFBundleIdentifier': 'com.example.runner.share',
          'NSContactsUsageDescription': 'TODO',
        }),
      );

      final result = await IosArtifactScanner().scan(fixture.appPath);
      final finding = result.failed.singleWhere(
        (finding) => finding.ruleId == 'ios.permission.contacts.empty',
      );

      expect(finding.path, contains('ShareExtension.appex/Info.plist'));
    },
  );

  test(
    'finds binary evidence beyond the old small file prefix window',
    () async {
      final fixture = await AppFixture.create();
      addTearDown(fixture.delete);

      fixture.writeInfoPlist(_validBasePlist());
      fixture.writeFile(
        'Frameworks/LargeCamera.framework/LargeCamera',
        '${'A' * (3 * 1024 * 1024)}AVCaptureSession',
      );

      final result = await IosArtifactScanner().scan(fixture.appPath);

      expectRule(result.warned, 'ios.permission.camera.missing');
    },
  );
}

void expectRule(List<LintFinding> findings, String ruleId) {
  expect(findings.map((finding) => finding.ruleId), contains(ruleId));
}

Map<String, Object?> _validBasePlist() => {
  'CFBundleIdentifier': 'com.example.runner',
  'CFBundleShortVersionString': '1.2.3',
  'CFBundleVersion': '45',
  'UILaunchStoryboardName': 'LaunchScreen',
  'UISupportedInterfaceOrientations': ['UIInterfaceOrientationPortrait'],
  'ITSAppUsesNonExemptEncryption': false,
};

class AppFixture {
  AppFixture._(this._root, this.appPath);

  final Directory _root;
  final String appPath;

  static Future<AppFixture> create() async {
    final root = await Directory.systemTemp.createTemp('fal_rule_matrix_');
    final app = Directory('${root.path}/Runner.app')..createSync();
    return AppFixture._(root, app.path);
  }

  void delete() => _root.deleteSync(recursive: true);

  void writeInfoPlist(Map<String, Object?> values) {
    File('$appPath/Info.plist').writeAsStringSync(_plist(values));
  }

  void writePrivacyManifest(List<Map<String, Object?>> apiTypes) {
    writeFile(
      'PrivacyInfo.xcprivacy',
      _plist({'NSPrivacyAccessedAPITypes': apiTypes}),
    );
  }

  void writeFramework(String name, String content) {
    writeFile('Frameworks/$name/${name.replaceAll('.framework', '')}', content);
  }

  void writeFile(String relativePath, String content) {
    final file = File('$appPath/$relativePath')..createSync(recursive: true);
    file.writeAsStringSync(content);
  }
}

String _plist(Map<String, Object?> values) {
  final buffer = StringBuffer()
    ..writeln('<?xml version="1.0" encoding="UTF-8"?>')
    ..writeln(
      '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
      '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
    )
    ..writeln('<plist version="1.0">')
    ..writeln(_dict(values))
    ..writeln('</plist>');
  return buffer.toString();
}

String _dict(Map<String, Object?> values) {
  final buffer = StringBuffer()..writeln('<dict>');
  for (final entry in values.entries) {
    buffer.writeln('<key>${entry.key}</key>');
    buffer.write(_value(entry.value));
  }
  buffer.writeln('</dict>');
  return buffer.toString();
}

String _value(Object? value) {
  if (value is bool) return value ? '<true/>\n' : '<false/>\n';
  if (value is List) {
    final buffer = StringBuffer()..writeln('<array>');
    for (final item in value) {
      buffer.write(_value(item));
    }
    buffer.writeln('</array>');
    return buffer.toString();
  }
  if (value is Map<String, Object?>) return _dict(value);
  return '<string>${value ?? ''}</string>\n';
}
