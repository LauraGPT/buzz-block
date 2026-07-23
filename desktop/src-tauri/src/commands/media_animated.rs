//! Structural metadata stripping for animated PNG and WebP uploads.
//!
//! Re-encoding an animated image through `image::DynamicImage` keeps only its
//! first frame. These helpers instead copy rendering chunks byte-for-byte while
//! dropping the metadata channels rejected by the relay.

const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";
const PNG_ALLOWED_ANCILLARY: &[[u8; 4]] = &[
    *b"cHRM", *b"gAMA", *b"sBIT", *b"sRGB", *b"bKGD", *b"hIST", *b"tRNS", *b"sPLT", *b"acTL",
    *b"fcTL", *b"fdAT",
];
const WEBP_ALLOWED_CHUNKS: &[[u8; 4]] =
    &[*b"VP8 ", *b"VP8L", *b"VP8X", *b"ALPH", *b"ANIM", *b"ANMF"];
const WEBP_METADATA_FLAGS: u8 = 0x20 | 0x08 | 0x04;

/// Strip metadata-bearing ancillary chunks from a PNG without touching frame
/// control or image data. Bytes after `IEND` are truncated.
pub(crate) fn strip_animated_png_metadata(body: &[u8]) -> Option<Vec<u8>> {
    if !body.starts_with(PNG_SIGNATURE) {
        return None;
    }

    let mut output = Vec::with_capacity(body.len());
    output.extend_from_slice(PNG_SIGNATURE);
    let mut offset = PNG_SIGNATURE.len();

    while offset < body.len() {
        let header_end = offset.checked_add(8)?;
        if header_end > body.len() {
            return None;
        }
        let payload_len = u32::from_be_bytes(body[offset..offset + 4].try_into().ok()?) as usize;
        let kind: [u8; 4] = body[offset + 4..offset + 8].try_into().ok()?;
        let chunk_end = offset
            .checked_add(12)?
            .checked_add(payload_len)
            .filter(|&end| end <= body.len())?;

        let ancillary = kind[0] & 0x20 != 0;
        if !ancillary || PNG_ALLOWED_ANCILLARY.contains(&kind) {
            output.extend_from_slice(&body[offset..chunk_end]);
        }

        offset = chunk_end;
        if kind == *b"IEND" {
            return Some(output);
        }
    }

    None
}

/// Strip metadata chunks and flags from a WebP container while retaining all
/// still/animated rendering chunks. RIFF padding is canonicalized to zero and
/// the container length is rewritten after removals.
pub(crate) fn strip_animated_webp_metadata(body: &[u8]) -> Option<Vec<u8>> {
    if body.len() < 12 || &body[..4] != b"RIFF" || &body[8..12] != b"WEBP" {
        return None;
    }

    let declared = u32::from_le_bytes(body[4..8].try_into().ok()?) as usize;
    let input_end = declared
        .checked_add(8)
        .filter(|&end| (12..=body.len()).contains(&end))?;
    let mut output = Vec::with_capacity(input_end);
    output.extend_from_slice(b"RIFF\0\0\0\0WEBP");
    let mut offset = 12usize;

    while offset < input_end {
        if offset.checked_add(8)? > input_end {
            return None;
        }
        let kind: [u8; 4] = body[offset..offset + 4].try_into().ok()?;
        let payload_len =
            u32::from_le_bytes(body[offset + 4..offset + 8].try_into().ok()?) as usize;
        let payload_start = offset + 8;
        let padded_len = payload_len.checked_add(payload_len & 1)?;
        let chunk_end = payload_start
            .checked_add(padded_len)
            .filter(|&end| end <= input_end)?;

        if WEBP_ALLOWED_CHUNKS.contains(&kind) {
            output.extend_from_slice(&kind);
            output.extend_from_slice(&(u32::try_from(payload_len).ok()?).to_le_bytes());
            if kind == *b"VP8X" {
                let (&flags, rest) =
                    body[payload_start..payload_start + payload_len].split_first()?;
                output.push(flags & !WEBP_METADATA_FLAGS);
                output.extend_from_slice(rest);
            } else {
                output.extend_from_slice(&body[payload_start..payload_start + payload_len]);
            }
            if payload_len & 1 != 0 {
                output.push(0);
            }
        }

        offset = chunk_end;
    }

    let riff_len = u32::try_from(output.len().checked_sub(8)?).ok()?;
    output[4..8].copy_from_slice(&riff_len.to_le_bytes());
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::media::sanitize_image_for_upload;

    fn png_chunk(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        chunk.extend_from_slice(kind);
        chunk.extend_from_slice(payload);
        // The structural sanitizer copies CRCs without interpreting them. A
        // zero placeholder keeps these focused tests dependency-free.
        chunk.extend_from_slice(&[0; 4]);
        chunk
    }

    fn animated_png(metadata: bool) -> Vec<u8> {
        let mut png = PNG_SIGNATURE.to_vec();
        png.extend_from_slice(&png_chunk(b"IHDR", &[0; 13]));
        png.extend_from_slice(&png_chunk(b"acTL", &[0, 0, 0, 2, 0, 0, 0, 0]));
        if metadata {
            png.extend_from_slice(&png_chunk(b"tEXt", b"Location\0secret"));
            png.extend_from_slice(&png_chunk(b"pHYs", &[0; 9]));
        }
        png.extend_from_slice(&png_chunk(b"fcTL", &[0; 26]));
        png.extend_from_slice(&png_chunk(b"IDAT", &[1, 2, 3]));
        png.extend_from_slice(&png_chunk(b"fdAT", &[0, 0, 0, 1, 4, 5]));
        png.extend_from_slice(&png_chunk(b"IEND", &[]));
        png
    }

    fn webp_chunk(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut chunk = Vec::new();
        chunk.extend_from_slice(kind);
        chunk.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        chunk.extend_from_slice(payload);
        if payload.len() & 1 != 0 {
            chunk.push(0);
        }
        chunk
    }

    fn animated_webp(metadata: bool) -> Vec<u8> {
        let metadata_flags = if metadata { WEBP_METADATA_FLAGS } else { 0 };
        let mut chunks = webp_chunk(b"VP8X", &[metadata_flags | 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        chunks.extend_from_slice(&webp_chunk(b"ANIM", &[0; 6]));
        if metadata {
            chunks.extend_from_slice(&webp_chunk(b"EXIF", b"location"));
            chunks.extend_from_slice(&webp_chunk(b"XMP ", b"<xmp/>"));
            chunks.extend_from_slice(&webp_chunk(b"JUNK", b"private"));
        }
        chunks.extend_from_slice(&webp_chunk(b"ANMF", &[0; 16]));

        let mut webp = b"RIFF".to_vec();
        webp.extend_from_slice(&((chunks.len() + 4) as u32).to_le_bytes());
        webp.extend_from_slice(b"WEBP");
        webp.extend_from_slice(&chunks);
        webp
    }

    #[test]
    fn test_strip_animated_png_metadata_preserves_animation_chunks() {
        assert_eq!(
            strip_animated_png_metadata(&animated_png(true)),
            Some(animated_png(false))
        );
    }

    #[test]
    fn test_strip_animated_png_metadata_is_byte_identical_for_clean_input() {
        let clean = animated_png(false);
        assert_eq!(strip_animated_png_metadata(&clean), Some(clean));
    }

    #[test]
    fn test_strip_animated_webp_metadata_preserves_animation_chunks() {
        assert_eq!(
            strip_animated_webp_metadata(&animated_webp(true)),
            Some(animated_webp(false))
        );
    }

    #[test]
    fn test_strip_animated_webp_metadata_is_byte_identical_for_clean_input() {
        let clean = animated_webp(false);
        assert_eq!(strip_animated_webp_metadata(&clean), Some(clean));
    }

    #[test]
    fn test_animated_sanitizers_truncate_trailing_bytes() {
        let clean_png = animated_png(false);
        let mut padded_png = clean_png.clone();
        padded_png.extend_from_slice(b"trailing metadata");
        assert_eq!(strip_animated_png_metadata(&padded_png), Some(clean_png));

        let clean_webp = animated_webp(false);
        let mut padded_webp = clean_webp.clone();
        padded_webp.extend_from_slice(b"trailing metadata");
        assert_eq!(strip_animated_webp_metadata(&padded_webp), Some(clean_webp));
    }

    #[test]
    fn test_animated_sanitizers_reject_malformed_containers() {
        assert!(strip_animated_png_metadata(PNG_SIGNATURE).is_none());
        assert!(strip_animated_webp_metadata(b"RIFF\x20\0\0\0WEBP").is_none());
    }

    #[test]
    fn test_upload_sanitizer_uses_structural_animation_scrubbers() {
        assert_eq!(
            sanitize_image_for_upload(animated_png(true), "image/png"),
            Ok(animated_png(false))
        );
        assert_eq!(
            sanitize_image_for_upload(animated_webp(true), "image/webp"),
            Ok(animated_webp(false))
        );
    }
}
