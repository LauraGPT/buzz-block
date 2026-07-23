import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:buzz/shared/relay/animated_image_sanitizer.dart';

void main() {
  test('strips APNG metadata without changing animation chunks', () {
    final clean = _animatedPng(metadata: false);
    final dirty = _animatedPng(metadata: true)
      ..addAll(utf8.encode('trailing metadata'));

    expect(
      sanitizeAnimatedImageForUpload(Uint8List.fromList(dirty), 'image/png'),
      clean,
    );
  });

  test('strips animated WebP metadata and clears metadata flags', () {
    final clean = _animatedWebp(metadata: false);
    final dirty = _animatedWebp(metadata: true)
      ..addAll(utf8.encode('trailing metadata'));

    expect(
      sanitizeAnimatedImageForUpload(Uint8List.fromList(dirty), 'image/webp'),
      clean,
    );
  });

  test('strips GIF metadata without changing animation blocks', () {
    final clean = _minimalGif();
    final dirty = <int>[
      ...clean.sublist(0, 19),
      ..._gifCommentExtension(),
      ..._gifApplicationExtension('XMP DataXMP', utf8.encode('<x/>')),
      ...clean.sublist(19),
      ...utf8.encode('trailing metadata'),
    ];

    expect(
      sanitizeAnimatedImageForUpload(Uint8List.fromList(dirty), 'image/gif'),
      clean,
    );
  });

  test('removes a GIF graphic control consumed by stripped plain text', () {
    final clean = _minimalGif();
    final dirty = <int>[
      ...clean.sublist(0, 19),
      0x21,
      0xf9,
      4,
      0x09,
      0x1e,
      0,
      1,
      0,
      ..._gifPlainTextExtension(),
      ...clean.sublist(19),
    ];

    expect(
      sanitizeAnimatedImageForUpload(Uint8List.fromList(dirty), 'image/gif'),
      clean,
    );
  });

  test('keeps clean animated containers byte-identical', () {
    for (final (mimeType, bytes) in [
      ('image/png', _animatedPng(metadata: false)),
      ('image/webp', _animatedWebp(metadata: false)),
      ('image/gif', _minimalGif()),
    ]) {
      expect(
        sanitizeAnimatedImageForUpload(Uint8List.fromList(bytes), mimeType),
        bytes,
      );
    }
  });

  test('fails closed for malformed animated containers', () {
    for (final (mimeType, bytes) in [
      ('image/png', <int>[0x89, 0x50, 0x4e, 0x47]),
      ('image/webp', ascii.encode('RIFFxxxxWEBP')),
      ('image/gif', ascii.encode('GIF89a')),
    ]) {
      expect(
        () =>
            sanitizeAnimatedImageForUpload(Uint8List.fromList(bytes), mimeType),
        throwsFormatException,
      );
    }
  });
}

List<int> _pngChunk(String type, List<int> payload) {
  return [
    ..._uint32BigEndian(payload.length),
    ...ascii.encode(type),
    ...payload,
    0,
    0,
    0,
    0,
  ];
}

List<int> _animatedPng({required bool metadata}) {
  return [
    0x89,
    0x50,
    0x4e,
    0x47,
    0x0d,
    0x0a,
    0x1a,
    0x0a,
    ..._pngChunk('IHDR', List.filled(13, 0)),
    ..._pngChunk('acTL', [0, 0, 0, 2, 0, 0, 0, 0]),
    if (metadata) ..._pngChunk('tEXt', utf8.encode('Location\u0000secret')),
    if (metadata) ..._pngChunk('pHYs', List.filled(9, 0)),
    ..._pngChunk('fcTL', List.filled(26, 0)),
    ..._pngChunk('IDAT', [1, 2, 3]),
    ..._pngChunk('fdAT', [0, 0, 0, 1, 4, 5]),
    ..._pngChunk('IEND', const []),
  ];
}

List<int> _webpChunk(String type, List<int> payload) {
  return [
    ...ascii.encode(type),
    ..._uint32LittleEndian(payload.length),
    ...payload,
    if (payload.length.isOdd) 0,
  ];
}

List<int> _animatedWebp({required bool metadata}) {
  final chunks = <int>[
    ..._webpChunk('VP8X', [
      0x02 | (metadata ? 0x2c : 0),
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
    ]),
    ..._webpChunk('ANIM', List.filled(6, 0)),
    if (metadata) ..._webpChunk('EXIF', utf8.encode('location')),
    if (metadata) ..._webpChunk('XMP ', utf8.encode('<xmp/>')),
    if (metadata) ..._webpChunk('JUNK', utf8.encode('private')),
    ..._webpChunk('ANMF', List.filled(16, 0)),
  ];
  return [
    ...ascii.encode('RIFF'),
    ..._uint32LittleEndian(chunks.length + 4),
    ...ascii.encode('WEBP'),
    ...chunks,
  ];
}

List<int> _minimalGif() {
  return [
    ...ascii.encode('GIF89a'),
    2,
    0,
    2,
    0,
    0x80,
    0,
    0,
    0,
    0,
    0,
    0xff,
    0xff,
    0xff,
    0x21,
    0xff,
    11,
    ...ascii.encode('NETSCAPE2.0'),
    3,
    1,
    0,
    0,
    0,
    0x21,
    0xf9,
    4,
    0,
    10,
    0,
    0,
    0,
    0x2c,
    0,
    0,
    0,
    0,
    2,
    0,
    2,
    0,
    0,
    2,
    2,
    0x44,
    1,
    0,
    0x3b,
  ];
}

List<int> _gifCommentExtension() {
  return [0x21, 0xfe, 5, ...ascii.encode('hello'), 0];
}

List<int> _gifApplicationExtension(String identifier, List<int> payload) {
  return [
    0x21,
    0xff,
    11,
    ...ascii.encode(identifier),
    payload.length,
    ...payload,
    0,
  ];
}

List<int> _gifPlainTextExtension() {
  return [0x21, 0x01, 12, 0, 0, 0, 0, 2, 0, 2, 0, 1, 1, 1, 0, 1, 0x78, 0];
}

List<int> _uint32BigEndian(int value) {
  return [
    value >> 24 & 0xff,
    value >> 16 & 0xff,
    value >> 8 & 0xff,
    value & 0xff,
  ];
}

List<int> _uint32LittleEndian(int value) {
  return [
    value & 0xff,
    value >> 8 & 0xff,
    value >> 16 & 0xff,
    value >> 24 & 0xff,
  ];
}
