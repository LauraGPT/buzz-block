import 'dart:convert';
import 'dart:typed_data';

const _pngSignature = <int>[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const _allowedPngAncillaryChunks = {
  'cHRM',
  'gAMA',
  'sBIT',
  'sRGB',
  'bKGD',
  'hIST',
  'tRNS',
  'sPLT',
  'acTL',
  'fcTL',
  'fdAT',
};
const _allowedWebpChunks = {'VP8 ', 'VP8L', 'VP8X', 'ALPH', 'ANIM', 'ANMF'};
const _webpMetadataFlags = 0x20 | 0x08 | 0x04;

/// Remove metadata from an animated image without decoding its frames.
///
/// Decoding through UIKit or Android Bitmap would flatten animations. These
/// structural scrubbers retain only the chunks/extensions accepted by the
/// relay and preserve animation timing, disposal, looping, and frame data.
Uint8List sanitizeAnimatedImageForUpload(Uint8List bytes, String mimeType) {
  return switch (mimeType) {
    'image/gif' => _scrubGif(bytes),
    'image/png' => _scrubPng(bytes),
    'image/webp' => _scrubWebp(bytes),
    _ => throw FormatException('Unsupported animated image type: $mimeType'),
  };
}

Uint8List _scrubPng(Uint8List bytes) {
  if (!_startsWith(bytes, _pngSignature)) {
    throw const FormatException('Invalid PNG signature');
  }

  final output = BytesBuilder(copy: false)..add(_pngSignature);
  var offset = _pngSignature.length;
  while (offset < bytes.length) {
    if (bytes.length - offset < 12) {
      throw const FormatException('Truncated PNG chunk');
    }
    final payloadLength = _readUint32BigEndian(bytes, offset);
    final chunkLength = payloadLength + 12;
    if (payloadLength > bytes.length - offset - 12) {
      throw const FormatException('Invalid PNG chunk length');
    }
    final typeStart = offset + 4;
    final type = ascii.decode(bytes.sublist(typeStart, typeStart + 4));
    final isAncillary = bytes[typeStart] & 0x20 != 0;
    if (!isAncillary || _allowedPngAncillaryChunks.contains(type)) {
      output.add(Uint8List.sublistView(bytes, offset, offset + chunkLength));
    }

    offset += chunkLength;
    if (type == 'IEND') {
      return output.takeBytes();
    }
  }

  throw const FormatException('PNG is missing IEND');
}

Uint8List _scrubWebp(Uint8List bytes) {
  if (bytes.length < 12 ||
      !_matchesAscii(bytes, 0, 'RIFF') ||
      !_matchesAscii(bytes, 8, 'WEBP')) {
    throw const FormatException('Invalid WebP signature');
  }

  final declaredLength = _readUint32LittleEndian(bytes, 4);
  final inputEnd = declaredLength + 8;
  if (inputEnd < 12 || inputEnd > bytes.length) {
    throw const FormatException('Invalid WebP container length');
  }

  final chunks = BytesBuilder(copy: false);
  var offset = 12;
  while (offset < inputEnd) {
    if (inputEnd - offset < 8) {
      throw const FormatException('Truncated WebP chunk');
    }
    final type = ascii.decode(bytes.sublist(offset, offset + 4));
    final payloadLength = _readUint32LittleEndian(bytes, offset + 4);
    final payloadStart = offset + 8;
    final paddedLength = payloadLength + (payloadLength.isOdd ? 1 : 0);
    final chunkEnd = payloadStart + paddedLength;
    if (chunkEnd > inputEnd) {
      throw const FormatException('Invalid WebP chunk length');
    }

    if (_allowedWebpChunks.contains(type)) {
      chunks.add(ascii.encode(type));
      chunks.add(_uint32LittleEndian(payloadLength));
      if (type == 'VP8X') {
        if (payloadLength == 0) {
          throw const FormatException('Invalid VP8X chunk');
        }
        chunks.addByte(bytes[payloadStart] & ~_webpMetadataFlags);
        chunks.add(
          Uint8List.sublistView(
            bytes,
            payloadStart + 1,
            payloadStart + payloadLength,
          ),
        );
      } else {
        chunks.add(
          Uint8List.sublistView(
            bytes,
            payloadStart,
            payloadStart + payloadLength,
          ),
        );
      }
      if (payloadLength.isOdd) {
        chunks.addByte(0);
      }
    }
    offset = chunkEnd;
  }

  final chunkBytes = chunks.takeBytes();
  final output = BytesBuilder(copy: false)
    ..add(ascii.encode('RIFF'))
    ..add(_uint32LittleEndian(chunkBytes.length + 4))
    ..add(ascii.encode('WEBP'))
    ..add(chunkBytes);
  return output.takeBytes();
}

Uint8List _scrubGif(Uint8List bytes) {
  if (bytes.length < 13 ||
      (!_matchesAscii(bytes, 0, 'GIF87a') &&
          !_matchesAscii(bytes, 0, 'GIF89a'))) {
    throw const FormatException('Invalid GIF signature');
  }

  var offset = 13;
  final packed = bytes[10];
  if (packed & 0x80 != 0) {
    final tableLength = 3 << ((packed & 0x07) + 1);
    offset += tableLength;
    if (offset > bytes.length) {
      throw const FormatException('Truncated GIF color table');
    }
  }

  final segments = <Uint8List?>[Uint8List.sublistView(bytes, 0, offset)];
  final pendingGraphicControls = <int>[];

  while (offset < bytes.length) {
    switch (bytes[offset]) {
      case 0x2c:
        final start = offset;
        if (bytes.length - offset < 10) {
          throw const FormatException('Truncated GIF image descriptor');
        }
        final imagePacked = bytes[offset + 9];
        offset += 10;
        if (imagePacked & 0x80 != 0) {
          offset += 3 << ((imagePacked & 0x07) + 1);
          if (offset > bytes.length) {
            throw const FormatException('Truncated GIF local color table');
          }
        }
        if (offset >= bytes.length) {
          throw const FormatException('Missing GIF LZW code size');
        }
        offset = _gifSubBlocksEnd(bytes, offset + 1);
        segments.add(Uint8List.sublistView(bytes, start, offset));
        pendingGraphicControls.clear();
      case 0x21:
        final start = offset;
        if (bytes.length - offset < 2) {
          throw const FormatException('Truncated GIF extension');
        }
        final label = bytes[offset + 1];
        offset += 2;
        switch (label) {
          case 0xf9:
            if (bytes.length - offset < 6 ||
                bytes[offset] != 4 ||
                bytes[offset + 5] != 0) {
              throw const FormatException('Invalid GIF graphic control');
            }
            offset += 6;
            segments.add(Uint8List.sublistView(bytes, start, offset));
            pendingGraphicControls.add(segments.length - 1);
          case 0xff:
            if (bytes.length - offset < 12 || bytes[offset] != 11) {
              throw const FormatException('Invalid GIF application extension');
            }
            final application = ascii.decode(
              bytes.sublist(offset + 1, offset + 12),
            );
            offset = _gifSubBlocksEnd(bytes, offset + 12);
            if (application == 'NETSCAPE2.0' || application == 'ANIMEXTS1.0') {
              segments.add(Uint8List.sublistView(bytes, start, offset));
            }
          case 0x01:
            offset = _gifSubBlocksEnd(bytes, offset);
            for (final segmentIndex in pendingGraphicControls) {
              segments[segmentIndex] = null;
            }
            pendingGraphicControls.clear();
          default:
            offset = _gifSubBlocksEnd(bytes, offset);
        }
      case 0x3b:
        segments.add(Uint8List.sublistView(bytes, offset, offset + 1));
        final output = BytesBuilder(copy: false);
        for (final segment in segments) {
          if (segment != null) output.add(segment);
        }
        return output.takeBytes();
      default:
        throw const FormatException('Invalid GIF block');
    }
  }

  throw const FormatException('GIF is missing trailer');
}

int _gifSubBlocksEnd(Uint8List bytes, int offset) {
  while (offset < bytes.length) {
    final blockLength = bytes[offset];
    offset += 1;
    if (blockLength == 0) return offset;
    offset += blockLength;
    if (offset > bytes.length) {
      throw const FormatException('Truncated GIF data block');
    }
  }
  throw const FormatException('GIF data blocks are missing a terminator');
}

bool _startsWith(Uint8List bytes, List<int> prefix) {
  if (bytes.length < prefix.length) return false;
  for (var index = 0; index < prefix.length; index += 1) {
    if (bytes[index] != prefix[index]) return false;
  }
  return true;
}

bool _matchesAscii(Uint8List bytes, int offset, String value) {
  final expected = ascii.encode(value);
  if (bytes.length - offset < expected.length) return false;
  for (var index = 0; index < expected.length; index += 1) {
    if (bytes[offset + index] != expected[index]) return false;
  }
  return true;
}

int _readUint32BigEndian(Uint8List bytes, int offset) {
  return ByteData.sublistView(bytes, offset, offset + 4).getUint32(0);
}

int _readUint32LittleEndian(Uint8List bytes, int offset) {
  return ByteData.sublistView(
    bytes,
    offset,
    offset + 4,
  ).getUint32(0, Endian.little);
}

Uint8List _uint32LittleEndian(int value) {
  return Uint8List(4)..buffer.asByteData().setUint32(0, value, Endian.little);
}
