import 'dart:convert';
import 'dart:io';

import 'package:xml/xml.dart';

class PlistParseException implements Exception {
  const PlistParseException(this.message);

  final String message;

  @override
  String toString() => message;
}

Map<String, Object?> parsePlistFile(String path) {
  final parsedByPlutil = _parseWithPlutil(path);
  if (parsedByPlutil != null) return parsedByPlutil;

  final content = File(path).readAsStringSync();
  return parsePlist(content);
}

Map<String, Object?>? _parseWithPlutil(String path) {
  if (!Platform.isMacOS) return null;

  try {
    final result = Process.runSync('plutil', [
      '-convert',
      'json',
      '-o',
      '-',
      path,
    ]);
    if (result.exitCode != 0) return null;
    final decoded = jsonDecode(result.stdout as String);
    if (decoded is! Map<String, Object?>) {
      throw const PlistParseException('Root is not a dictionary');
    }
    return decoded;
  } on PlistParseException {
    rethrow;
  } catch (_) {
    return null;
  }
}

Map<String, Object?> parsePlist(String content) {
  late final XmlDocument document;
  try {
    document = XmlDocument.parse(content);
  } on XmlException catch (error) {
    throw PlistParseException(error.message);
  }

  final dict = document.descendants.whereType<XmlElement>().firstWhere(
    (element) => element.name.local == 'dict',
    orElse: () => throw const PlistParseException('Missing root dict'),
  );

  return _parseDict(dict);
}

Map<String, Object?> _parseDict(XmlElement dict) {
  final values = <String, Object?>{};
  final children = dict.children.whereType<XmlElement>().toList();

  for (var i = 0; i < children.length; i++) {
    final keyElement = children[i];
    if (keyElement.name.local != 'key') continue;
    if (i + 1 >= children.length) break;

    values[keyElement.innerText] = _parseValue(children[i + 1]);
    i++;
  }

  return values;
}

Object? _parseValue(XmlElement element) {
  return switch (element.name.local) {
    'string' => element.innerText,
    'integer' => int.tryParse(element.innerText),
    'real' => double.tryParse(element.innerText),
    'true' => true,
    'false' => false,
    'array' =>
      element.children.whereType<XmlElement>().map(_parseValue).toList(),
    'dict' => _parseDict(element),
    _ => element.innerText,
  };
}
