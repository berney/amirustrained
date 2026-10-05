use flate2::read::GzDecoder;
use std::io::{self, Read};

#[allow(dead_code)]
pub fn decompress_gz(bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(bytes);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    #[test]
    fn roundtrip_gzip_decompression() {
        let input = b"CONFIG_MODULES=y\nCONFIG_KEXEC=y\n";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(input).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed = decompress_gz(&compressed).expect("decompression succeeds");
        assert_eq!(decompressed, input);
    }

    #[test]
    fn malformed_gzip_fails_gracefully() {
        let bad = b"\x1f\x8b\x08garbage";
        assert!(decompress_gz(bad).is_err());
    }
}
