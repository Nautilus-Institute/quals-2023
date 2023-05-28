extern crate libc;

use std::ptr;
use libc::{c_int};

#[repr(C)]
struct EvpPkeyRsa {
    _data: [u8; 0],
    _marker:
        core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

const SIG_SIZE: usize = 256;
const OWNER_CERT_HEADER_SIZE: usize = 16;
const OWNER_CERT_OWNER_NAME_SIZE: usize = 64;
const OWNER_CERT_DEVICE_NAME_SIZE: usize = 16;
const OWNER_CERT_PADDING_SIZE: usize = 32;
const MAX_OWNERSHIP_CERT_SIZE: usize = SIG_SIZE +
                                       OWNER_CERT_HEADER_SIZE +
                                       OWNER_CERT_OWNER_NAME_SIZE +
                                       OWNER_CERT_DEVICE_NAME_SIZE +
                                       OWNER_CERT_PADDING_SIZE;

const KEY_CERT_KEY_DATA_SIZE: usize = 32;
const MAX_KEY_CERT_SIZE: usize = SIG_SIZE +
                                 KEY_CERT_KEY_DATA_SIZE;

const NV_STORAGE_CERT_DATA_SIZE: usize = 1024;
const MAX_NV_STORAGE_CERT_SIZE: usize = SIG_SIZE +
                                        NV_STORAGE_CERT_DATA_SIZE;

extern "C" {
    fn sfm_init_ek() -> *const EvpPkeyRsa;
    fn sfm_get_public_key(pkey: *const EvpPkeyRsa,
                          output: *mut u8) -> c_int;
    fn sfm_attest_to_quote(pkey: *const EvpPkeyRsa,
                           alg_id: u16,
                           banks: *const [u8; 64],
                           num_banks: usize,
                           output: *mut u8) -> c_int;
    fn sfm_certify_owner_record(pkey: *const EvpPkeyRsa,
                   owner_name: *const u8,
                   device_name: *const u8,
                   serial: u64,
                   timestamp: u32,
                   output: *mut u8) -> c_int;
    fn sfm_certify_key(pkey: *const EvpPkeyRsa,
                       key_data: *const u8,
                       output: *mut u8) -> c_int;
    fn sfm_certify_nv_storage(pkey: *const EvpPkeyRsa,
                              data: *const u8,
                              data_len: usize,
                              output: *mut u8) -> c_int;
}

pub struct SecureFirmwareModule {
    ek: *const EvpPkeyRsa
}

impl SecureFirmwareModule {
    pub fn new() -> SecureFirmwareModule {
       SecureFirmwareModule {
        ek: ptr::null(),
       }
    }

    pub fn init(&mut self) -> i32 {
        let pkey = unsafe {
            let pkey = sfm_init_ek();
            if pkey == ptr::null() {
                return -1;
            }
            pkey
        };
        self.ek = pkey;
        0
    }

    pub fn get_public_key(&self) -> Option<Vec<u8>> {
        let mut out_buf = [0u8; 512];
        let err = unsafe {
            sfm_get_public_key(self.ek, out_buf.as_mut_ptr())
        };

        if err != 0 {
            None
        } else {
            Some(out_buf.to_vec())
        }
    }

    pub fn attest(&self,
                  alg_id: u16,
                  banks: Vec<[u8; 64]>) -> Option<Vec<u8>> {
        let mut out_buf = [0u8; 512];
        let err = unsafe {
            sfm_attest_to_quote(self.ek,
                                alg_id as u16,
                                banks.as_ptr(),
                                banks.len(),
                                out_buf.as_mut_ptr())
        };

        if err != 0 {
            None
        } else {
            Some(out_buf.to_vec())
        }
    }

    pub fn certify_ownership_record(&mut self,
                                    owner_name: &[u8],
                                    device_name: &[u8],
                                    serial: u64,
                                    timestamp: u32) -> Option<Vec<u8>> {
        let mut out_buf = [0u8; MAX_OWNERSHIP_CERT_SIZE];

        let err = unsafe {
            sfm_certify_owner_record(self.ek,
                                     owner_name.as_ptr(),
                                     device_name.as_ptr(),
                                     serial,
                                     timestamp,
                                     out_buf.as_mut_ptr())
        };

        if err != 0 {
            None
        } else {
            Some(out_buf.to_vec())
        }
    }

    pub fn certify_key(&mut self, key_data: &[u8]) -> Option<Vec<u8>> {
        let mut out_buf = [0u8; MAX_KEY_CERT_SIZE];

        let err = unsafe {
            sfm_certify_key(self.ek,
                            key_data.as_ptr(),
                            out_buf.as_mut_ptr())
        };

        if err != 0 {
            None
        } else {
            Some(out_buf.to_vec())
        }
    }

    pub fn certify_nv_storage(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let mut out_buf = [0u8; MAX_NV_STORAGE_CERT_SIZE];

        let err = unsafe {
            sfm_certify_nv_storage(self.ek,
                                   data.as_ptr(),
                                   data.len(),
                                   out_buf.as_mut_ptr())
        };

        if err != 0 {
            None
        } else {
            Some(out_buf.to_vec())
        }
    }
}
