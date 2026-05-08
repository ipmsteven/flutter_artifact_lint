import 'dart:convert';
import 'dart:io';

import 'package:flutter_artifact_lint/src/cli.dart';
import 'package:path/path.dart' as p;
import 'package:test/test.dart';

void main() {
  final selected = _selectedScenarios();
  for (final scenario in _scenarios.where(selected.contains)) {
    test(
      'real Flutter plugin matrix: ${scenario.id}',
      () async {
        if (!Platform.isMacOS) {
          print('Skipping: iOS Flutter plugin builds require macOS.');
          return;
        }
        if (!_commandExists('flutter')) {
          print('Skipping: flutter is not available on PATH.');
          return;
        }
        if (!_commandExists('xcodebuild')) {
          print('Skipping: xcodebuild is not available on PATH.');
          return;
        }

        final tempDir = await Directory.systemTemp.createTemp(
          'fal_plugin_${scenario.id}_',
        );
        addTearDown(() => tempDir.delete(recursive: true));

        final create = await Process.run('flutter', [
          'create',
          '--platforms=ios',
          '--project-name',
          'plugin_app',
          '--org',
          'com.example',
          '.',
        ], workingDirectory: tempDir.path).timeout(const Duration(minutes: 2));
        expect(
          create.exitCode,
          0,
          reason: 'flutter create failed\n${create.stdout}\n${create.stderr}',
        );

        _addExportComplianceFlag(tempDir.path);

        final add = await Process.run('flutter', [
          'pub',
          'add',
          ...scenario.packages,
        ], workingDirectory: tempDir.path).timeout(const Duration(minutes: 5));
        expect(
          add.exitCode,
          0,
          reason:
              'flutter pub add failed for ${scenario.id}\n${add.stdout}\n${add.stderr}',
        );
        _setMinimumIosDeploymentTarget(tempDir.path, '15.0');
        _enableIosPermissionMacros(tempDir.path, scenario.iosPermissionMacros);

        final build = await Process.run('flutter', [
          'build',
          'ios',
          '--release',
          '--no-tree-shake-icons',
          '--no-codesign',
        ], workingDirectory: tempDir.path).timeout(const Duration(minutes: 20));
        expect(
          build.exitCode,
          0,
          reason:
              'flutter build ios failed for ${scenario.id}\n${build.stdout}\n${build.stderr}',
        );

        final result = await runCli([
          'ios',
          '--format',
          'json',
          '--fail-on',
          'none',
        ], workingDirectory: tempDir.path);
        expect(
          result.exitCode,
          0,
          reason: 'scan failed\n${result.stdout}\n${result.stderr}',
        );

        final payload = jsonDecode(result.stdout) as Map<String, Object?>;
        final findings = (payload['findings'] as List<Object?>)
            .cast<Map<String, Object?>>();
        final ruleIds = findings
            .map((finding) => finding['ruleId'] as String)
            .toSet();

        expect(
          ruleIds,
          containsAll(scenario.expectedRuleIds),
          reason:
              '${scenario.id} expected plugin evidence was not reported.\n'
              'Reported rules: ${ruleIds.toList()..sort()}',
        );
        for (final absentRuleId in scenario.absentRuleIds) {
          expect(
            ruleIds,
            isNot(contains(absentRuleId)),
            reason: '${scenario.id} unexpectedly reported $absentRuleId.',
          );
        }

        expect(ruleIds, contains('ios.macho.architecture'));
        expect(ruleIds, contains('ios.macho.build_version'));
      },
      timeout: const Timeout(Duration(minutes: 30)),
    );
  }
}

Set<_PluginScenario> _selectedScenarios() {
  final filter = Platform.environment['FAL_PLUGIN_MATRIX_SHARD'];
  if (filter == null || filter.trim().isEmpty || filter == 'all') {
    return _scenarios.toSet();
  }
  final requested = filter
      .split(',')
      .map((value) => value.trim())
      .where((value) => value.isNotEmpty)
      .toSet();
  return _scenarios
      .where(
        (scenario) =>
            requested.contains(scenario.id) ||
            requested.contains(scenario.shard),
      )
      .toSet();
}

void _setMinimumIosDeploymentTarget(String appPath, String version) {
  final podfile = File(p.join(appPath, 'ios', 'Podfile'));
  final content = podfile.readAsStringSync();
  if (content.contains("platform :ios, '$version'")) return;
  podfile.writeAsStringSync(
    content.replaceFirst(
      RegExp(r"#?\s*platform :ios, '[^']+'"),
      "platform :ios, '$version'",
    ),
  );
}

void _enableIosPermissionMacros(String appPath, List<String> macros) {
  if (macros.isEmpty) return;

  final podfile = File(p.join(appPath, 'ios', 'Podfile'));
  final content = podfile.readAsStringSync();
  const marker = '# flutter_artifact_lint plugin matrix permission macros';
  if (content.contains(marker)) return;

  final macroEntries = macros
      .map((macro) => "            '$macro',")
      .join('\n');
  const needle = '    flutter_additional_ios_build_settings(target)\n';
  expect(
    content,
    contains(needle),
    reason: 'Generated Flutter Podfile changed shape unexpectedly.',
  );

  podfile.writeAsStringSync(
    content.replaceFirst(needle, '''
$needle$marker
      target.build_configurations.each do |config|
        config.build_settings['GCC_PREPROCESSOR_DEFINITIONS'] ||= [
          '\$(inherited)',
        ]
        config.build_settings['GCC_PREPROCESSOR_DEFINITIONS'] += [
$macroEntries
        ]
      end
'''),
  );
}

void _addExportComplianceFlag(String appPath) {
  final plistPath = p.join(appPath, 'ios', 'Runner', 'Info.plist');
  final plist = File(plistPath);
  final plistContent = plist.readAsStringSync();
  if (plistContent.contains('ITSAppUsesNonExemptEncryption')) return;
  final rootDictEnd = plistContent.lastIndexOf('</dict>');
  expect(rootDictEnd, greaterThan(0));
  plist.writeAsStringSync('''
${plistContent.substring(0, rootDictEnd)}
\t<key>ITSAppUsesNonExemptEncryption</key>
\t<false/>
</dict>
${plistContent.substring(rootDictEnd + '</dict>'.length)}''');
}

bool _commandExists(String command) {
  final result = Process.runSync('which', [command]);
  return result.exitCode == 0;
}

const _scenarios = [
  _PluginScenario(
    id: 'camera-media',
    shard: 'permissions-a',
    packages: ['camera:0.12.0+1', 'image_picker:1.2.2', 'photo_manager:3.9.0'],
    expectedRuleIds: [
      'ios.permission.camera.missing',
      'ios.permission.photos.missing',
    ],
  ),
  _PluginScenario(
    id: 'location-contacts',
    shard: 'permissions-a',
    packages: ['geolocator:14.0.1', 'flutter_contacts:2.0.2'],
    expectedRuleIds: [
      'ios.permission.location.missing',
      'ios.permission.contacts.missing',
    ],
  ),
  _PluginScenario(
    id: 'notification-auth',
    shard: 'permissions-b',
    packages: ['flutter_local_notifications:21.0.0', 'local_auth:3.0.1'],
    expectedRuleIds: [
      'ios.notification.evidence',
      'ios.permission.face_id.missing',
    ],
  ),
  _PluginScenario(
    id: 'bluetooth-speech',
    shard: 'permissions-b',
    packages: ['flutter_blue_plus:2.3.1', 'speech_to_text:7.3.0'],
    expectedRuleIds: [
      'ios.permission.bluetooth.missing',
      'ios.permission.microphone.missing',
    ],
  ),
  _PluginScenario(
    id: 'required-reason-storage',
    shard: 'platform',
    packages: [
      'shared_preferences:2.5.5',
      'path_provider:2.1.5',
      'device_info_plus:13.1.0',
    ],
    expectedRuleIds: ['ios.required_reason.disk_space'],
  ),
  _PluginScenario(
    id: 'webview-url',
    shard: 'platform',
    packages: ['webview_flutter:4.13.1', 'url_launcher:6.3.2'],
    expectedRuleIds: ['ios.dynamic_code_execution.evidence'],
    absentRuleIds: ['ios.private_api.uiwebview'],
  ),
  _PluginScenario(
    id: 'permission-handler',
    shard: 'ecosystem',
    packages: ['permission_handler:12.0.1'],
    iosPermissionMacros: _permissionHandlerMacros,
    expectedRuleIds: [
      'ios.permission.camera.missing',
      'ios.permission.contacts.missing',
      'ios.permission.location.missing',
      'ios.permission.photos.missing',
      'ios.permission.bluetooth.missing',
      'ios.permission.microphone.missing',
      'ios.notification.evidence',
    ],
  ),
  _PluginScenario(
    id: 'firebase-notification',
    shard: 'ecosystem',
    packages: ['firebase_core:4.7.0', 'firebase_messaging:16.2.0'],
    expectedRuleIds: ['ios.notification.evidence'],
  ),
  _PluginScenario(
    id: 'comprehensive-all',
    shard: 'ecosystem',
    packages: [
      'camera:0.12.0+1',
      'image_picker:1.2.2',
      'photo_manager:3.9.0',
      'geolocator:14.0.1',
      'flutter_contacts:2.0.2',
      'flutter_local_notifications:21.0.0',
      'local_auth:3.0.1',
      'shared_preferences:2.5.5',
      'path_provider:2.1.5',
      'device_info_plus:13.1.0',
      'flutter_blue_plus:2.3.1',
      'speech_to_text:7.3.0',
      'webview_flutter:4.13.1',
      'url_launcher:6.3.2',
      'permission_handler:12.0.1',
      'firebase_core:4.7.0',
      'firebase_messaging:16.2.0',
    ],
    iosPermissionMacros: _permissionHandlerMacros,
    expectedRuleIds: [
      'ios.notification.evidence',
      'ios.permission.bluetooth.missing',
      'ios.permission.camera.missing',
      'ios.permission.contacts.missing',
      'ios.permission.face_id.missing',
      'ios.permission.location.missing',
      'ios.permission.microphone.missing',
      'ios.permission.photos.missing',
      'ios.required_reason.disk_space',
    ],
  ),
];

class _PluginScenario {
  const _PluginScenario({
    required this.id,
    required this.shard,
    required this.packages,
    required this.expectedRuleIds,
    this.absentRuleIds = const [],
    this.iosPermissionMacros = const [],
  });

  final String id;
  final String shard;
  final List<String> packages;
  final List<String> expectedRuleIds;
  final List<String> absentRuleIds;
  final List<String> iosPermissionMacros;
}

const _permissionHandlerMacros = [
  'PERMISSION_CONTACTS=1',
  'PERMISSION_CAMERA=1',
  'PERMISSION_MICROPHONE=1',
  'PERMISSION_SPEECH_RECOGNIZER=1',
  'PERMISSION_PHOTOS=1',
  'PERMISSION_LOCATION=1',
  'PERMISSION_LOCATION_WHENINUSE=0',
  'PERMISSION_NOTIFICATIONS=1',
  'PERMISSION_BLUETOOTH=1',
];
