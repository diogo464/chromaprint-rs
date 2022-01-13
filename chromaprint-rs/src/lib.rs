use std::{
    ffi::CStr,
    os::raw::{c_char, c_int, c_uint},
};

use chromaprint_sys::*;

#[derive(Debug)]
pub struct ChromaprintError(&'static str);

pub type Result<T, E = ChromaprintError> = std::result::Result<T, E>;

impl std::fmt::Display for ChromaprintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("chromaprint error : ")?;
        f.write_str(self.0)?;
        Ok(())
    }
}

impl std::error::Error for ChromaprintError {}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum Algorithm {
    TEST1,
    TEST2,
    TEST3,
    TEST4,
    TEST5,
}

impl Default for Algorithm {
    fn default() -> Self {
        Self::from_c_int(ChromaprintAlgorithm_CHROMAPRINT_ALGORITHM_DEFAULT as c_int)
    }
}

impl Algorithm {
    fn to_c_int(self) -> c_int {
        match self {
            Algorithm::TEST1 => ChromaprintAlgorithm_CHROMAPRINT_ALGORITHM_TEST1 as c_int,
            Algorithm::TEST2 => ChromaprintAlgorithm_CHROMAPRINT_ALGORITHM_TEST2 as c_int,
            Algorithm::TEST3 => ChromaprintAlgorithm_CHROMAPRINT_ALGORITHM_TEST3 as c_int,
            Algorithm::TEST4 => ChromaprintAlgorithm_CHROMAPRINT_ALGORITHM_TEST4 as c_int,
            Algorithm::TEST5 => ChromaprintAlgorithm_CHROMAPRINT_ALGORITHM_TEST5 as c_int,
        }
    }

    #[allow(non_upper_case_globals)]
    fn from_c_int(algorithm: c_int) -> Algorithm {
        match algorithm as u32 {
            ChromaprintAlgorithm_CHROMAPRINT_ALGORITHM_TEST1 => Self::TEST1,
            ChromaprintAlgorithm_CHROMAPRINT_ALGORITHM_TEST2 => Self::TEST2,
            ChromaprintAlgorithm_CHROMAPRINT_ALGORITHM_TEST3 => Self::TEST3,
            ChromaprintAlgorithm_CHROMAPRINT_ALGORITHM_TEST4 => Self::TEST4,
            ChromaprintAlgorithm_CHROMAPRINT_ALGORITHM_TEST5 => Self::TEST5,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug)]
pub struct RawFingerprint {
    // Algorithm used to encode this fingerprint
    algorithm: Algorithm,
    container: RawFingerprintContainer,
}

impl RawFingerprint {
    fn native(algorithm: Algorithm, data: *mut c_uint, size: c_int) -> Self {
        Self {
            algorithm,
            container: RawFingerprintContainer::Native { data, size },
        }
    }

    pub fn new(algorithm: Algorithm, data: Vec<u32>) -> Self {
        Self {
            algorithm,
            container: RawFingerprintContainer::User { data },
        }
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    // TODO: redo/remove
    pub fn size(&self) -> usize {
        match &self.container {
            RawFingerprintContainer::Native { size, .. } => *size as usize,
            RawFingerprintContainer::User { data } => data.len(),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match &self.container {
            RawFingerprintContainer::Native { data, size } => unsafe {
                let len = (*size as usize) * std::mem::size_of::<c_uint>();
                let ptr = (*data) as *const u8;
                std::slice::from_raw_parts(ptr, len)
            },
            RawFingerprintContainer::User { data } => unsafe {
                let ptr = data.as_ptr() as *const u8;
                let len = data.len() * std::mem::size_of::<u32>();
                std::slice::from_raw_parts(ptr, len)
            },
        }
    }

    pub fn as_slice(&self) -> &[u32] {
        match &self.container {
            RawFingerprintContainer::Native { data, size } => unsafe {
                let len = (*size as usize) * std::mem::size_of::<c_uint>();
                let ptr = (*data) as *const u32;
                std::slice::from_raw_parts(ptr, len)
            },
            RawFingerprintContainer::User { data } => data.as_slice(),
        }
    }

    pub fn encode(&self, base64: bool) -> Result<Fingerprint> {
        encode_fingerprint(self.as_slice(), self.algorithm(), base64)
    }

    pub fn encode_base64(&self) -> Result<FingerprintBase64> {
        encode_fingerprint_base64(self.as_slice(), self.algorithm())
    }

    pub fn encode_compressed(&self) -> Result<FingerprintCompressed> {
        encode_fingerprint_compressed(self.as_slice(), self.algorithm())
    }
}

#[derive(Debug)]
enum RawFingerprintContainer {
    Native { data: *mut c_uint, size: c_int },
    User { data: Vec<u32> },
}

unsafe impl Send for RawFingerprintContainer {}
unsafe impl Sync for RawFingerprintContainer {}

impl Drop for RawFingerprintContainer {
    fn drop(&mut self) {
        if let Self::Native { data, .. } = self {
            unsafe { chromaprint_dealloc((*data) as *mut _) }
        }
    }
}

#[derive(Debug)]
pub struct FingerprintBase64(FingerprintBase64Inner);

impl std::fmt::Display for FingerprintBase64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FingerprintBase64 {
    fn native(ptr: *const c_char) -> Self {
        Self(FingerprintBase64Inner::Native(ptr))
    }

    pub fn new(base64: String) -> Self {
        Self(FingerprintBase64Inner::User(base64))
    }

    pub fn as_str(&self) -> &str {
        match &self.0 {
            FingerprintBase64Inner::Native(ptr) => unsafe {
                let cstr = CStr::from_ptr(*ptr);
                cstr.to_str().expect("base64 should be valid utf8")
            },
            FingerprintBase64Inner::User(string) => string.as_str(),
        }
    }

    pub fn decode(&self) -> Result<RawFingerprint> {
        decode_base64_fingerprint(self.as_str())
    }
}

#[derive(Debug)]
enum FingerprintBase64Inner {
    Native(*const c_char),
    User(String),
}

unsafe impl Send for FingerprintBase64Inner {}
unsafe impl Sync for FingerprintBase64Inner {}

impl Drop for FingerprintBase64Inner {
    fn drop(&mut self) {
        if let Self::Native(ptr) = self {
            unsafe { chromaprint_dealloc((*ptr) as *mut _) }
        }
    }
}

#[derive(Debug)]
pub struct FingerprintCompressed(FingerprintCompressedInner);

impl std::fmt::Display for FingerprintCompressed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let raw = self.decode().map_err(|_| std::fmt::Error)?;
        let encoded = raw.encode_base64().map_err(|_| std::fmt::Error)?;
        encoded.fmt(f)
    }
}

impl FingerprintCompressed {
    fn native(ptr: *const c_char, size: c_int) -> Self {
        Self(FingerprintCompressedInner::Native(ptr, size))
    }

    pub fn new(data: Vec<u8>) -> Self {
        Self(FingerprintCompressedInner::User(data))
    }

    pub fn as_bytes(&self) -> &[u8] {
        match &self.0 {
            FingerprintCompressedInner::Native(ptr, size) => unsafe {
                std::slice::from_raw_parts(*ptr as *const u8, *size as usize)
            },
            FingerprintCompressedInner::User(data) => data.as_slice(),
        }
    }

    pub fn decode(&self) -> Result<RawFingerprint> {
        decode_compressed_fingerprint(self.as_bytes())
    }
}

#[derive(Debug)]
enum FingerprintCompressedInner {
    Native(*const c_char, c_int),
    User(Vec<u8>),
}

unsafe impl Send for FingerprintCompressedInner {}
unsafe impl Sync for FingerprintCompressedInner {}

impl Drop for FingerprintCompressedInner {
    fn drop(&mut self) {
        if let Self::Native(ptr, _) = self {
            unsafe { chromaprint_dealloc((*ptr) as *mut _) }
        }
    }
}

#[derive(Debug)]
pub enum Fingerprint {
    Base64(FingerprintBase64),
    Compressed(FingerprintCompressed),
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fingerprint::Base64(inner) => inner.fmt(f),
            Fingerprint::Compressed(inner) => inner.fmt(f),
        }
    }
}

impl From<FingerprintBase64> for Fingerprint {
    fn from(base64: FingerprintBase64) -> Self {
        Self::Base64(base64)
    }
}

impl From<FingerprintCompressed> for Fingerprint {
    fn from(compressed: FingerprintCompressed) -> Self {
        Self::Compressed(compressed)
    }
}

impl Fingerprint {
    fn native_base64(ptr: *const c_char) -> Self {
        Self::Base64(FingerprintBase64::native(ptr))
    }

    fn native_compressed(ptr: *const c_char, size: c_int) -> Self {
        Self::Compressed(FingerprintCompressed::native(ptr, size))
    }

    pub fn decode(&self) -> Result<RawFingerprint> {
        match self {
            Fingerprint::Base64(base64) => base64.decode(),
            Fingerprint::Compressed(compressed) => compressed.decode(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
#[repr(C)]
pub struct FingerprintHash(u32);

impl FingerprintHash {
    pub fn new(hash: u32) -> Self {
        Self(hash)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum ContextOption {
    SilenceThreshold,
}

impl ContextOption {
    fn option_c_string(&self) -> *const c_char {
        const SILENCE_THRESHOLD_BYTES: &[u8] = b"silence_threshold\0";
        match self {
            Self::SilenceThreshold => CStr::from_bytes_with_nul(SILENCE_THRESHOLD_BYTES)
                .unwrap()
                .as_ptr(),
        }
    }
}

#[derive(Debug, Hash)]
pub struct Chroma {
    ctx: *mut ChromaprintContextPrivate,
}

unsafe impl Send for Chroma {}

impl Default for Chroma {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl Drop for Chroma {
    fn drop(&mut self) {
        unsafe { chromaprint_free(self.ctx) }
    }
}

impl Chroma {
    pub fn new(algorithm: Algorithm) -> Self {
        let ctx = unsafe { chromaprint_new(algorithm.to_c_int()) };
        assert_ne!(ctx, std::ptr::null_mut());
        Self { ctx }
    }

    pub fn algorithm(&self) -> Algorithm {
        let alg = unsafe { chromaprint_get_algorithm(self.ctx) };
        Algorithm::from_c_int(alg)
    }

    // return true on success
    pub fn set_option(&self, option: ContextOption, value: i32) -> Result<()> {
        let err = unsafe { chromaprint_set_option(self.ctx, option.option_c_string(), value) };
        convert_err(err, "set_option")
    }

    pub fn num_channels(&self) -> u32 {
        unsafe { chromaprint_get_num_channels(self.ctx) as u32 }
    }

    pub fn sample_rate(&self) -> u32 {
        unsafe { chromaprint_get_sample_rate(self.ctx) as u32 }
    }

    pub fn item_duration(&self) -> u32 {
        unsafe { chromaprint_get_item_duration(self.ctx) as u32 }
    }

    pub fn item_duration_ms(&self) -> u32 {
        unsafe { chromaprint_get_item_duration_ms(self.ctx) as u32 }
    }

    pub fn delay(&self) -> u32 {
        unsafe { chromaprint_get_delay(self.ctx) as u32 }
    }

    pub fn delay_ms(&self) -> u32 {
        unsafe { chromaprint_get_delay_ms(self.ctx) as u32 }
    }

    pub fn start(&self, sample_rate: u32, num_channels: u32) -> Result<()> {
        let err = unsafe { chromaprint_start(self.ctx, sample_rate as i32, num_channels as i32) };
        convert_err(err, "start")
    }

    pub fn feed(&self, data: &[i16]) -> Result<()> {
        let size = data.len();
        let err = unsafe { chromaprint_feed(self.ctx, data.as_ptr(), size as i32) };
        convert_err(err, "feed")
    }

    pub fn finish(&self) -> Result<()> {
        let err = unsafe { chromaprint_finish(self.ctx) };
        convert_err(err, "finish")
    }

    pub fn fingerprint(&self) -> Result<Fingerprint> {
        let mut ptr: *mut char = std::ptr::null_mut();
        let err = unsafe {
            chromaprint_get_fingerprint(self.ctx, std::ptr::addr_of_mut!(ptr) as *mut *mut i8)
        };
        convert_err(err, "fingerprint")?;
        assert_ne!(ptr, std::ptr::null_mut());
        Ok(Fingerprint::native_base64(ptr as *const _))
    }

    pub fn raw_fingerprint(&self) -> Result<RawFingerprint> {
        let algorithm = self.algorithm();
        let mut size: c_int = 0;
        let mut data: *mut c_uint = std::ptr::null_mut();
        let err = unsafe {
            chromaprint_get_raw_fingerprint(
                self.ctx,
                std::ptr::addr_of_mut!(data),
                std::ptr::addr_of_mut!(size),
            )
        };
        convert_err(err, "raw_fingerprint")?;
        assert_ne!(data, std::ptr::null_mut());
        Ok(RawFingerprint::native(algorithm, data, size))
    }

    pub fn raw_fingerprint_size(&self) -> Result<u32> {
        let mut size: c_int = 0;
        let err =
            unsafe { chromaprint_get_raw_fingerprint_size(self.ctx, std::ptr::addr_of_mut!(size)) };
        convert_err(err, "raw_fingerprint_size")?;
        Ok(size as u32)
    }

    pub fn fingerprint_hash(&self) -> Result<FingerprintHash> {
        let mut hash: c_uint = 0;
        let err =
            unsafe { chromaprint_get_fingerprint_hash(self.ctx, std::ptr::addr_of_mut!(hash)) };
        convert_err(err, "fingerprint_hash")?;
        Ok(FingerprintHash(hash))
    }

    pub fn clear_fingerprint(&self) -> Result<()> {
        let err = unsafe { chromaprint_clear_fingerprint(self.ctx) };
        convert_err(err, "clear_fingerprint")
    }
}

pub fn get_version() -> &'static str {
    unsafe {
        let cstr = CStr::from_ptr(chromaprint_get_version());
        let bytes = cstr.to_bytes();
        std::str::from_utf8_unchecked(bytes)
    }
}

pub fn encode_fingerprint(raw: &[u32], algorithm: Algorithm, base64: bool) -> Result<Fingerprint> {
    let algorithm = algorithm.to_c_int();
    let fp = raw.as_ptr() as *const c_uint;
    let size = raw.len() as c_int;
    let mut encoded: *mut c_char = std::ptr::null_mut();
    let mut encoded_size: c_int = 0;
    let base64_cint = if base64 { 1 } else { 0 };
    let err = unsafe {
        chromaprint_encode_fingerprint(
            fp,
            size,
            algorithm,
            std::ptr::addr_of_mut!(encoded),
            std::ptr::addr_of_mut!(encoded_size),
            base64_cint,
        )
    };
    convert_err(err, "encode_fingerprint")?;
    assert_ne!(encoded, std::ptr::null_mut());
    let fingerprint = match base64 {
        true => Fingerprint::native_base64(encoded),
        false => Fingerprint::native_compressed(encoded, encoded_size),
    };
    Ok(fingerprint)
}

pub fn encode_fingerprint_base64(raw: &[u32], algorithm: Algorithm) -> Result<FingerprintBase64> {
    match encode_fingerprint(raw, algorithm, true)? {
        Fingerprint::Base64(base64) => Ok(base64),
        Fingerprint::Compressed(_) => unreachable!(),
    }
}

pub fn encode_fingerprint_compressed(
    raw: &[u32],
    algorithm: Algorithm,
) -> Result<FingerprintCompressed> {
    match encode_fingerprint(raw, algorithm, false)? {
        Fingerprint::Base64(_) => unreachable!(),
        Fingerprint::Compressed(compressed) => Ok(compressed),
    }
}

pub fn decode_fingerprint(fingerprint: &Fingerprint) -> Result<RawFingerprint> {
    match fingerprint {
        Fingerprint::Base64(base64) => decode_base64_fingerprint(base64.as_str()),
        Fingerprint::Compressed(compressed) => decode_compressed_fingerprint(compressed.as_bytes()),
    }
}

pub fn decode_base64_fingerprint(fingerprint: &str) -> Result<RawFingerprint> {
    let encoded_fp = fingerprint.as_bytes();
    let encoded_size = encoded_fp.len() as c_int;
    decode_fingerprint_helper(encoded_fp.as_ptr() as *const _, encoded_size)
}

pub fn decode_compressed_fingerprint(fingerprint: &[u8]) -> Result<RawFingerprint> {
    decode_fingerprint_helper(fingerprint.as_ptr() as *const _, fingerprint.len() as c_int)
}

fn decode_fingerprint_helper(
    encoded_fp: *const c_char,
    encoded_size: c_int,
) -> Result<RawFingerprint> {
    let mut raw: *mut c_uint = std::ptr::null_mut();
    let mut raw_size: c_int = 0;
    let mut algorithm_cint: c_int = 0;
    let err = unsafe {
        chromaprint_decode_fingerprint(
            encoded_fp,
            encoded_size,
            std::ptr::addr_of_mut!(raw),
            std::ptr::addr_of_mut!(raw_size),
            std::ptr::addr_of_mut!(algorithm_cint),
            1,
        )
    };
    convert_err(err, "decode_fingerprint_helper")?;
    assert_ne!(raw, std::ptr::null_mut());
    let algorithm = Algorithm::from_c_int(algorithm_cint);
    Ok(RawFingerprint::native(algorithm, raw, raw_size))
}

pub fn hash_fingerprint(raw: &[u32]) -> Result<FingerprintHash> {
    let ptr = raw.as_ptr() as *const c_uint;
    let size = raw.len() as c_int;
    let mut hash = 0;
    let err = unsafe { chromaprint_hash_fingerprint(ptr, size, std::ptr::addr_of_mut!(hash)) };
    convert_err(err, "hash_fingerprint")?;
    Ok(FingerprintHash(hash))
}

// return Err if `err == FAILURE` and provide a context string to give the error some more information
fn convert_err(err: i32, context: &'static str) -> Result<(), ChromaprintError> {
    const FAILURE: i32 = 0;
    const SUCCESS: i32 = 1;

    match err {
        FAILURE => Err(ChromaprintError(context)),
        SUCCESS => Ok(()),
        _ => unreachable!(),
    }
}
