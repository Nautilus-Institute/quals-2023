#![allow(non_upper_case_globals)]
use zerocopy::{AsBytes, FromBytes, LayoutVerified};
use std::ops::Deref;

#[derive(Eq, PartialEq)]
pub struct SfmCommandCode(pub u16);

impl SfmCommandCode {
    pub const GetIdentity: Self = SfmCommandCode(0);
    pub const IntegrityBankUpdate: Self = SfmCommandCode(1);
    pub const CreateObject: Self = SfmCommandCode(2);
    pub const ModifyObject: Self = SfmCommandCode(3);
    pub const DuplicateObject: Self = SfmCommandCode(4);
    pub const UnsealObject: Self = SfmCommandCode(5);
    pub const CertifyObject: Self = SfmCommandCode(6);
    pub const AttestQuote: Self = SfmCommandCode(7);
    pub const EstablishSecureIo: Self = SfmCommandCode(8);
}

#[derive(Eq, PartialEq)]
pub struct SfmAuthorizationPolicyCode(pub u16);

impl SfmAuthorizationPolicyCode {
    pub const NullPolicy: Self = SfmAuthorizationPolicyCode(0);
    pub const PcrPolicy: Self = SfmAuthorizationPolicyCode(1);
    pub const PasswordPolicy: Self = SfmAuthorizationPolicyCode(2);
}

#[derive(Debug)]
pub struct OwnershipRecord {
    pub country_code: String,
    pub owner_name: String,
    pub device_name: [u8; 16],
    pub serial_number: [u8; 8],
    pub creation_date: u32
}

impl From<OwnershipRecordRaw> for OwnershipRecord {
    fn from(item: OwnershipRecordRaw) -> Self {
        Self {
            country_code: String::from_utf8_lossy(&item.country_code[..]).to_string(),
            owner_name: String::from_utf8_lossy(&item.owner_name[..]).to_string(),
            device_name: item.device_name,
            serial_number: item.serial_number,
            creation_date: item.creation_date
        }
    }
}

#[repr(C)]
#[derive(Debug, AsBytes, FromBytes)]
pub struct OwnershipRecordRaw {
    pub country_code: [u8; 2],
    pub _padding: [u8; 2],
    pub owner_name: [u8; 64],
    pub device_name: [u8; 16],
    pub serial_number: [u8; 8],
    pub creation_date: u32,
}

#[repr(C)]
#[derive(Debug, AsBytes, FromBytes)]
pub struct Aes256Key {
    pub key_data: [u8; 32]
}

#[repr(C)]
#[derive(Debug, AsBytes, FromBytes)]
pub struct NvStorageRaw {
    pub size: u16,
}

#[derive(Debug)]
pub enum SfmObject {
    OwnershipRecord(OwnershipRecord),
    Key(Aes256Key),
    NvStorage(Vec<u8>),
}

#[derive(Debug)]
pub enum SfmHashAlgorithm {
    HashAlgSha1   = 0,
    HashAlgSha256 = 1,
    HashAlgSha384 = 2,
    HashAlgSha512 = 3,
    HashAlgMax    = 4,
}

#[derive(Debug)]
pub enum SfmObjectType {
    OwnershipRecord = 1,
    Key,
    NvStorage,
}

impl TryFrom<u16> for SfmObjectType {
    type Error = ();

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(SfmObjectType::OwnershipRecord),
            2 => Ok(SfmObjectType::Key),
            3 => Ok(SfmObjectType::NvStorage),
            _ => Err(())
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum AuthorizationPolicy {
    NullPolicy,
    PcrPolicy([[u8; 64]; 4]),
    PasswordPolicy([u8; 64]),
}

#[derive(Debug)]
pub struct ObjectStoreItem {
    pub policy: AuthorizationPolicy,
    pub item: SfmObject
}

#[repr(C)]
#[derive(AsBytes, FromBytes)]
pub struct SfmCommand {
    _reservered: u32,
    command_code: u16,
    pad_: u16,
}

impl SfmCommand {
    pub fn get_command_code(&self) -> SfmCommandCode {
        SfmCommandCode(self.command_code)
    }
}

#[repr(C)]
#[derive(AsBytes, FromBytes)]
pub struct SfmGetIdentity { }

#[repr(C)]
#[derive(AsBytes, FromBytes)]
pub struct SfmIntegrityBankUpdate {
    bank_index: u16,
    _pad: u16,
    data: [u8; 1024],
}

impl SfmIntegrityBankUpdate {
    pub fn get_bank_index(&self) -> u16 {
        self.bank_index
    }

    pub fn get_data(&self) -> &[u8] {
        &self.data[..]
    }
}

#[repr(C)]
#[derive(AsBytes, FromBytes)]
pub struct SfmCreateObject {
    object_type: u16
}

impl SfmCreateObject {
    pub fn get_object_type(&self) -> u16 {
        self.object_type
    }
}

pub const SFM_ESTABLISH_SECURE_STDIN:  u16 = 0b0001;
pub const SFM_ESTABLISH_SECURE_STDOUT: u16 = 0b0010;

#[repr(C)]
#[derive(AsBytes, FromBytes)]
pub struct SfmEstablishSecureIo {
    pub flags: u16
}

#[repr(C)]
#[derive(Debug, AsBytes, FromBytes)]
pub struct SfmKeyedHash {
    decrypt: u32,
}

/// Generic packet header struct. Allows parsing layers off of
/// a nested struct
pub struct WithTrailer<'a, T> {
    inner: &'a T,
    trailer: &'a [u8]
}

impl<T> WithTrailer<'_, T> {
    pub fn get_trailer(&self) -> &[u8] {
        self.trailer
    }
}

impl<T> Deref for WithTrailer<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[repr(C)]
#[derive(AsBytes, FromBytes)]
pub struct SfmModifyObject {
    pub object_index: u32,
}

impl SfmModifyObject {

    pub fn get_object_index(&self) -> u32 {
        self.object_index
    }
}

#[repr(C)]
#[derive(AsBytes, FromBytes)]
pub struct SfmCertifyObject
{
    pub object_index: u32,
}

#[repr(C)]
#[derive(Debug, AsBytes, FromBytes)]
pub struct SfmAuthorizationPolicy {
    policy_type: u16,
    pub data: [u8; 64]
}

#[repr(C)]
#[derive(Debug, AsBytes, FromBytes)]
pub struct SfmAttestQuote {
    pub alg_id: u16,
}

impl SfmAuthorizationPolicy {
    pub fn get_policy_type(&self) -> SfmAuthorizationPolicyCode {
        SfmAuthorizationPolicyCode(self.policy_type)
    }
}

pub trait JustBytes {
    /// parse and return a reference to the underlying data and the trailer
    fn parse_with_trailer(bytes: &[u8]) -> Option<WithTrailer<Self>>
        where Self: Sized;

    /// construct a new copy of Self using `bytes` as a source
    fn new_from_bytes(bytes: &[u8]) -> Option<Self>
        where Self: Sized;
}

impl<T: AsBytes + FromBytes> JustBytes for T {

    fn parse_with_trailer(bytes: &[u8]) -> Option<WithTrailer<T>>
      where Self: Sized
    {
        let (content, trailer) = LayoutVerified::<&[u8], Self>::new_from_prefix(bytes)?;
        Some(WithTrailer::<T>{ inner: content.into_ref(), trailer })
    }
    
    fn new_from_bytes(bytes: &[u8]) -> Option<Self>
      where Self: Sized
    {
        Self::read_from(bytes)
    }
}
