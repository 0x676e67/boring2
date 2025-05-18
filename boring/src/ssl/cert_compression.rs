use boring_sys as ffi;
use std::{io::Read, slice};

/// IANA assigned identifier of compression algorithm.
/// See https://www.rfc-editor.org/rfc/rfc8879.html#name-compression-algorithms
#[deprecated(
    since = "4.15.13",
    note = "This enum is deprecated and will be removed in a future version. \
            Use `boring::ssl::CertificateCompressionAlgorithm` instead."
)]
#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CertCompressionAlgorithm {
    /// The Brotli compression algorithm.
    Brotli = ffi::TLSEXT_cert_compression_brotli as _,
    /// The zlib compression algorithm.
    Zlib = ffi::TLSEXT_cert_compression_zlib as _,
    /// The Zstandard compression algorithm.
    Zstd = ffi::TLSEXT_cert_compression_zstd as _,
}

impl CertCompressionAlgorithm {
    /// Returns the compression function for the algorithm.
    pub(crate) fn compression_fn(&self) -> ffi::ssl_cert_compression_func_t {
        match &self {
            Self::Brotli => Some(brotli_compressor),
            Self::Zlib => Some(zlib_compressor),
            Self::Zstd => Some(zstd_compressor),
        }
    }

    /// Returns the decompression function for the algorithm.
    pub(crate) fn decompression_fn(&self) -> ffi::ssl_cert_decompression_func_t {
        match &self {
            Self::Brotli => Some(brotli_decompressor),
            Self::Zlib => Some(zlib_decompressor),
            Self::Zstd => Some(zstd_decompressor),
        }
    }
}

extern "C" fn brotli_compressor(
    _ssl: *mut ffi::SSL,
    buffer: *mut ffi::CBB,
    in_: *const u8,
    in_len: usize,
) -> ::std::os::raw::c_int {
    let mut uncompressed = unsafe { slice::from_raw_parts(in_, in_len) };
    let mut compressed = Vec::new();

    let params = brotli::enc::encode::BrotliEncoderInitParams();

    if brotli::BrotliCompress(&mut uncompressed, &mut compressed, &params).is_err() {
        return 0;
    }

    unsafe { ffi::CBB_add_bytes(buffer, compressed.as_ptr(), compressed.len()) }
}

extern "C" fn zlib_compressor(
    _ssl: *mut ffi::SSL,
    out: *mut ffi::CBB,
    in_: *const u8,
    in_len: usize,
) -> ::std::os::raw::c_int {
    let mut uncompressed = unsafe { slice::from_raw_parts(in_, in_len) };
    let mut compressed = Vec::new();

    let params = flate2::Compression::default();

    let mut encoder = flate2::bufread::ZlibEncoder::new(&mut uncompressed, params);
    if encoder.read_to_end(&mut compressed).is_err() {
        return 0;
    }

    unsafe { ffi::CBB_add_bytes(out, compressed.as_ptr(), compressed.len()) }
}

extern "C" fn zstd_compressor(
    _ssl: *mut ffi::SSL,
    out: *mut ffi::CBB,
    in_: *const u8,
    in_len: usize,
) -> ::std::os::raw::c_int {
    let mut uncompressed = unsafe { slice::from_raw_parts(in_, in_len) };

    let compressed = if let Ok(compressed) = zstd::encode_all(&mut uncompressed, 3) {
        compressed
    } else {
        return 0;
    };

    unsafe { ffi::CBB_add_bytes(out, compressed.as_ptr(), compressed.len()) }
}

extern "C" fn brotli_decompressor(
    _ssl: *mut ffi::SSL,
    buffer: *mut *mut ffi::CRYPTO_BUFFER,
    uncompressed_len: usize,
    in_: *const u8,
    in_len: usize,
) -> ::std::os::raw::c_int {
    let compressed = unsafe { slice::from_raw_parts(in_, in_len) };
    let mut uncompressed = Vec::with_capacity(uncompressed_len);

    if brotli::BrotliDecompress(&mut &compressed[..], &mut uncompressed).is_err() {
        return 0;
    }

    if uncompressed.len() != uncompressed_len {
        return 0;
    }

    unsafe {
        *buffer = ffi::CRYPTO_BUFFER_new(
            uncompressed.as_ptr(),
            uncompressed_len,
            std::ptr::null_mut(),
        );

        if buffer.is_null() {
            return 0;
        }
    }

    1
}

extern "C" fn zlib_decompressor(
    _ssl: *mut ffi::SSL,
    buffer: *mut *mut ffi::CRYPTO_BUFFER,
    uncompressed_len: usize,
    in_: *const u8,
    in_len: usize,
) -> ::std::os::raw::c_int {
    let mut compressed = unsafe { slice::from_raw_parts(in_, in_len) };
    let mut uncompressed = Vec::with_capacity(uncompressed_len);

    let mut decoder = flate2::bufread::ZlibDecoder::new(&mut compressed);
    if decoder.read_to_end(&mut uncompressed).is_err() {
        return 0;
    }

    if uncompressed.len() != uncompressed_len {
        return 0;
    }

    unsafe {
        *buffer = ffi::CRYPTO_BUFFER_new(
            uncompressed.as_ptr(),
            uncompressed_len,
            std::ptr::null_mut(),
        );

        if buffer.is_null() {
            return 0;
        }
    }

    1
}

extern "C" fn zstd_decompressor(
    _ssl: *mut ffi::SSL,
    buffer: *mut *mut ffi::CRYPTO_BUFFER,
    uncompressed_len: usize,
    in_: *const u8,
    in_len: usize,
) -> ::std::os::raw::c_int {
    let mut compressed = unsafe { slice::from_raw_parts(in_, in_len) };

    let uncompressed = if let Ok(uncompressed) = zstd::decode_all(&mut compressed) {
        uncompressed
    } else {
        return 0;
    };

    if uncompressed.len() != uncompressed_len {
        return 0;
    }

    unsafe {
        *buffer = ffi::CRYPTO_BUFFER_new(
            uncompressed.as_ptr(),
            uncompressed_len,
            std::ptr::null_mut(),
        );

        if buffer.is_null() {
            return 0;
        }
    }

    1
}
