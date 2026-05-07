import 'dart:io';

import 'package:path/path.dart' as p;

class EvidenceReport {
  const EvidenceReport({
    required this.tokens,
    required this.sourcesByToken,
    required this.scannedFiles,
  });

  final Set<String> tokens;
  final Map<String, Set<String>> sourcesByToken;
  final List<String> scannedFiles;

  List<String> matched(List<String> candidates) {
    return candidates.where(tokens.contains).toList();
  }
}

class IosEvidenceExtractor {
  const IosEvidenceExtractor({
    required this.tokens,
    this.maxBytesPerFile = 16 * 1024 * 1024,
  });

  final List<String> tokens;
  final int maxBytesPerFile;

  EvidenceReport collect(String appPath) {
    final found = <String>{};
    final sources = <String, Set<String>>{};
    final scannedFiles = <String>[];

    void addEvidence(String token, String sourcePath) {
      found.add(token);
      sources.putIfAbsent(token, () => <String>{}).add(sourcePath);
    }

    for (final entity in Directory(
      appPath,
    ).listSync(recursive: true, followLinks: false)) {
      final basename = p.basename(entity.path);
      if (basename.endsWith('.framework')) {
        addEvidence(basename, entity.path);
      }

      if (entity is! File || _shouldSkip(entity.path)) continue;
      final bytes = _readPrefix(entity);
      if (bytes.isEmpty) continue;

      scannedFiles.add(entity.path);
      final text = _asciiText(bytes);
      for (final token in tokens) {
        if (text.contains(token)) addEvidence(token, entity.path);
      }
    }

    return EvidenceReport(
      tokens: found,
      sourcesByToken: sources,
      scannedFiles: scannedFiles,
    );
  }

  List<int> _readPrefix(File file) {
    try {
      final raf = file.openSync();
      try {
        final length = raf.lengthSync();
        final size = length > maxBytesPerFile ? maxBytesPerFile : length;
        return raf.readSync(size);
      } finally {
        raf.closeSync();
      }
    } catch (_) {
      return const [];
    }
  }

  bool _shouldSkip(String path) {
    final ext = p.extension(path).toLowerCase();
    return {
      '.png',
      '.jpg',
      '.jpeg',
      '.gif',
      '.webp',
      '.car',
      '.storyboardc',
    }.contains(ext);
  }
}

String _asciiText(List<int> bytes) {
  final buffer = StringBuffer();
  for (final byte in bytes) {
    if (byte == 0x09 || byte == 0x0a || byte == 0x0d) {
      buffer.writeCharCode(0x20);
    } else if (byte >= 0x20 && byte <= 0x7e) {
      buffer.writeCharCode(byte);
    } else {
      buffer.writeCharCode(0x20);
    }
  }
  return buffer.toString();
}
