use std::{io, env};
use std::io::IoSlice;
use std::error::Error;
use std::io::{Read, Write};
use std::collections::HashMap;
use std::os::unix::net::UnixStream;
use std::os::fd::{AsRawFd, FromRawFd};
use std::time::{SystemTime, UNIX_EPOCH};

use nix::sys::socket;
use thiserror::Error;

use rand::RngCore;

use sha2::{Sha512, Digest};

use sfm::sfm_proto::*;

const SFMI_MAGIC: &[u8; 4] = b"SFMI";
const MAX_SFM_COMMAND: usize = 2048;

#[derive(Debug, Error)]
enum SfmError {
    #[error("Invalid command code {0}")]
    InvalidCommandCode(u16),
    #[error("Invalid command structure for")]
    InvalidCommandStructure,
    #[error("Invalid object type {0}")]
    InvalidObjectType(u16),
    #[error("Invalid object value {0:?}")]
    InvalidObjectValue(SfmObjectType),
    #[error("Invalid object store index {0}")]
    InvalidObjectIndex(u32),
    #[error("Invalid algorithm type")]
    InvalidAlgorithmType,
    #[error("Invalid authorization policy specified")]
    InvalidAuthPolicy,
    #[error("Failed authentication for object")]
    FailedAuth,
    #[error("Secure Firmware Module internal error")]
    SfmInternalError,
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error)
}

impl TryInto<u32> for SfmError {
    type Error = &'static str;

    fn try_into(self) -> Result<u32, Self::Error> {
        match self {
            SfmError::InvalidCommandCode(_) => Ok(0),
            SfmError::InvalidCommandStructure => Ok(1),
            SfmError::InvalidObjectType(_) => Ok(2),
            SfmError::InvalidObjectValue(_) => Ok(3),
            SfmError::InvalidObjectIndex(_) => Ok(4),
            SfmError::InvalidAlgorithmType => Ok(5),
            SfmError::InvalidAuthPolicy => Ok(6),
            SfmError::FailedAuth => Ok(7),
            SfmError::SfmInternalError => Ok(8),
            SfmError::IoError(_) => Ok(9),
        }
    }
}

type SfmResult<T> = Result<T, SfmError>;

struct SfmHandler {
    sfm: sfm_sys::SecureFirmwareModule,
    stream: UnixStream,
    banks: [[u8; 64]; 4],
    last_object_id: u64,
    object_store: HashMap<u64, ObjectStoreItem>,
    secure_io_policy: AuthorizationPolicy
}

impl SfmHandler {

    fn new(stream: UnixStream) -> Self {
        let mut sfm = sfm_sys::SecureFirmwareModule::new();

        sfm.init();

        let mut object_store = HashMap::new();
        let ownership_record = OwnershipRecord {
            country_code: String::from("US"),
            owner_name: String::from("NI Securable Products (c)"),
            device_name: *b"Secure Firmware\x00",
            serial_number: [0x23, 0x20, 0x4e, 0x4f, 0x43, 0x46, 0x45, 0x44],
            creation_date: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .expect("strange time encountered")
                            .as_secs() as u32,
        };

        // register state
        let pcr_policy = AuthorizationPolicy::PcrPolicy([
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [175, 105, 0, 44, 166, 180, 17, 198, 178, 144, 28, 117, 97, 43, 171, 56, 148, 190, 40, 137, 249, 167, 246, 148, 15, 116, 91, 154, 46, 167, 190, 167, 149, 94, 166, 225, 61, 117, 30, 124, 99, 119, 164, 106, 15, 183, 146, 51, 86, 219, 112, 207, 29, 66, 248, 66, 166, 76, 37, 186, 6, 31, 104, 141],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        ]);

        let res = object_store.insert(0,
            ObjectStoreItem {
                policy: pcr_policy.clone(),
                item: SfmObject::OwnershipRecord (
                    ownership_record
                )
            }
        );

        assert!(res.is_none(), "Unexpected object store state on init");

        Self {
            sfm: sfm,
            stream: stream,
            banks: [[0u8; 64]; 4],
            last_object_id: 1, // 0 is always the object_id of the ownership record
            object_store: object_store,
            secure_io_policy: pcr_policy
        }
    }

    fn get_identity(&mut self, _cmd: WithTrailer<SfmGetIdentity>) -> SfmResult<bool> {

        let identity = self.sfm.get_public_key();

        let identity_blob = identity.ok_or(SfmError::SfmInternalError)?;
        self.stream.write_all(&identity_blob[..])?;
        Ok(true)
    }

    fn integrity_bank_update(&mut self, cmd: WithTrailer<SfmIntegrityBankUpdate>) -> SfmResult<bool> {
        let bank_index = cmd.get_bank_index() as usize;

        if bank_index >= self.banks.len() {
            eprintln!("Invalid bank index specified");
            return Ok(false);
        }

        let mut hasher = Sha512::new();
        hasher.update(&self.banks[bank_index][..]);
        hasher.update(cmd.get_data());

        self.banks[bank_index] = hasher.finalize().into();

        self.stream.write_all(&(0_u32.to_le_bytes()))?;
        Ok(true)
    }

    fn create_object(&mut self, cmd: WithTrailer<SfmCreateObject>) -> SfmResult<bool> {
        // first strip off the desired policy
        let policy_header = SfmAuthorizationPolicy::parse_with_trailer(cmd.get_trailer())
            .ok_or(SfmError::InvalidAuthPolicy)?;

        // Some ugly logic here to update trailer
        let policy = match policy_header.get_policy_type() {
            SfmAuthorizationPolicyCode::NullPolicy => {
                AuthorizationPolicy::NullPolicy
            },
            SfmAuthorizationPolicyCode::PcrPolicy => {
                // create new policy with the existing PCR state
                AuthorizationPolicy::PcrPolicy(self.banks.clone())
            }
            SfmAuthorizationPolicyCode::PasswordPolicy => {
                AuthorizationPolicy::PasswordPolicy(
                    Sha512::digest(&policy_header.data[..])
                    .as_slice().try_into().unwrap()
                )
            }
            _ => Err(SfmError::InvalidAuthPolicy)?
        };

        // create the object, return the id
        let object: Option<SfmObject> = match cmd.get_object_type().try_into() {
            // OwnershipRecord is not a creatable object type
            Ok(SfmObjectType::OwnershipRecord) => None,
            Ok(SfmObjectType::Key) => {
                let mut key_data = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut key_data);
                Some(SfmObject::Key(Aes256Key { key_data } ))
            },
            Ok(SfmObjectType::NvStorage) => {
                let nv_storage_raw = NvStorageRaw::parse_with_trailer(policy_header.get_trailer())
                    .ok_or(SfmError::InvalidObjectValue(SfmObjectType::NvStorage))?;

                let size = nv_storage_raw.size as usize;
                if size > 1024 {
                    Err(SfmError::InvalidObjectValue(SfmObjectType::NvStorage))?;
                }

                Some(SfmObject::NvStorage(nv_storage_raw.get_trailer()[..size].to_vec()))
            }
            _ => None
        };

        let response_id = if let Some(object) = object {
            let object_with_policy = ObjectStoreItem {
                policy: policy,
                item: object
            };

            self.object_store.insert(self.last_object_id, object_with_policy);
            self.last_object_id.checked_add(1).expect("Object ID count overflowed");
            self.last_object_id - 1
        } else {
            eprintln!("Invalid object found");
            return Err(SfmError::InvalidObjectType(cmd.get_object_type()));
        };

        self.stream.write_all(&(response_id as u32).to_le_bytes())?;
        Ok(true)
    }

    fn modify_object(&mut self, cmd: WithTrailer<SfmModifyObject>) -> SfmResult<bool> {
        let idx = cmd.get_object_index();

        // look up object
        let entry = self.object_store.get_mut(&idx.into())
            .ok_or(SfmError::InvalidObjectIndex(idx))?;

        let policy_header = SfmAuthorizationPolicy::parse_with_trailer(cmd.get_trailer())
            .ok_or(SfmError::InvalidAuthPolicy)?;

        let (authorized, trailer) = match entry.policy {
            AuthorizationPolicy::NullPolicy => (true, cmd.get_trailer()),
            AuthorizationPolicy::PcrPolicy(desired_state) => {
                (self.banks == desired_state, cmd.get_trailer())
            },
            AuthorizationPolicy::PasswordPolicy(crypt_password) => {
                (Sha512::digest(&policy_header.data[..]).as_slice() == crypt_password,
                 policy_header.get_trailer())
            }
        };

        if !authorized {
            return Err(SfmError::FailedAuth);
        }

        // modify according to type and set fields
        let new_object = match entry.item {
            SfmObject::OwnershipRecord(_) => {
                SfmObject::OwnershipRecord(
                  OwnershipRecordRaw::new_from_bytes(trailer)
                  .ok_or(SfmError::InvalidObjectValue(SfmObjectType::OwnershipRecord))?
                  .into()
                )
            }
            SfmObject::Key(_) => {
                if trailer.len() != 32 {
                    Err(SfmError::InvalidObjectValue(SfmObjectType::Key))?;
                }
                let mut key_data = [0u8; 32];
                key_data.copy_from_slice(trailer);

                SfmObject::Key(Aes256Key { key_data } )
            }
            SfmObject::NvStorage(_) => {
                let nv_storage_raw = NvStorageRaw::parse_with_trailer(trailer)
                    .ok_or(SfmError::InvalidObjectValue(SfmObjectType::NvStorage))?;

                let size = nv_storage_raw.size as usize;
                if size > 1024 {
                    Err(SfmError::InvalidObjectValue(SfmObjectType::NvStorage))?;
                }

                SfmObject::NvStorage(nv_storage_raw.get_trailer()[..size].to_vec())
            }
        };

        let new_entry = ObjectStoreItem {
            policy: entry.policy,
            item: new_object
        };

        *entry = new_entry;

        self.stream.write_all(&(idx as u32).to_le_bytes())?;

        Ok(true)
    }

    fn certify_object(&mut self, cmd: WithTrailer<SfmCertifyObject>) -> SfmResult<bool> {
        let entry = self.object_store.get(&cmd.object_index.into())
            .ok_or(SfmError::InvalidObjectIndex(cmd.object_index))?;

        let certification = match &entry.item {
            SfmObject::OwnershipRecord(body) => {
                self.sfm.certify_ownership_record(
                           &body.owner_name.as_bytes(),
                           &body.device_name[..],
                           u64::from_le_bytes(body.serial_number),
                           body.creation_date)
            }
            SfmObject::Key(key) => {
                self.sfm.certify_key(&key.key_data[..])
            }
            SfmObject::NvStorage(data) => {
                self.sfm.certify_nv_storage(&data[..])
            }
        };

        // write the cert blob back out
        let cert_blob = certification.ok_or(SfmError::SfmInternalError)?;
        self.stream.write_all(&cert_blob[..])?;
        Ok(true)
    }

    fn attest_quote(&mut self, cmd: WithTrailer<SfmAttestQuote>) -> SfmResult<bool> {
        let alg = cmd.alg_id;

        if alg > SfmHashAlgorithm::HashAlgMax as u16 {
            return Err(SfmError::InvalidAlgorithmType);
        }

        let report = self.sfm.attest(alg, self.banks.to_vec());

        self.stream.write_all(&report.ok_or(SfmError::SfmInternalError)?[..])?;
        Ok(true)
    }

    fn establish_secure_io(&mut self, cmd: WithTrailer<SfmEstablishSecureIo>) -> SfmResult<bool> {
        let flags = cmd.flags;

        let approved = match self.secure_io_policy {
            AuthorizationPolicy::PcrPolicy(desired_state) => {
                self.banks == desired_state
            },
            _ => panic!("Secure IO set with unsupported policy type"),
        };

        if !approved {
            return Err(SfmError::FailedAuth);
        }

        let mut fds = vec![];
        if flags & SFM_ESTABLISH_SECURE_STDIN != 0 {
            fds.push(0);
        }

        if flags & SFM_ESTABLISH_SECURE_STDOUT != 0 {
            fds.push(1);
        }

        let fd_count = (fds.len() as u32).to_le_bytes();
        let iov = [IoSlice::new(&fd_count)];

        let cmsg = socket::ControlMessage::ScmRights(&fds[..]);
        socket::sendmsg::<()>(self.stream.as_raw_fd(), &iov, &[cmsg], socket::MsgFlags::empty(), None).unwrap();

        Ok(true)
    }

    fn respond_with_error(&mut self, error: SfmError) -> SfmResult<()> {
        // returns Ok or an IoError
        let error_code: u32 = error.try_into().unwrap();

        self.stream.write_all(&(u32::MAX - error_code).to_le_bytes())?;
        Ok(())
    }

    fn handshake(&mut self) -> SfmResult<bool> {
        self.stream.write_all(SFMI_MAGIC)?;

        let mut magic_resp = vec![0u8; 4];
        self.stream.read_exact(&mut magic_resp)?;

        Ok(SFMI_MAGIC == &magic_resp[..])
    }

    fn interface(&mut self) -> SfmResult<()> {
        let success = self.handshake()?;

        while success {
            let mut buf: [u8; MAX_SFM_COMMAND] = [0u8; MAX_SFM_COMMAND];
            let n = self.stream.read(&mut buf)?;

            if let Some(cmd) = SfmCommand::parse_with_trailer(&buf[..n]) {
                let process_result = match cmd.get_command_code() {
                    SfmCommandCode::GetIdentity => {
                        if let Some(get_identity) = SfmGetIdentity::parse_with_trailer(cmd.get_trailer()) {
                            self.get_identity(get_identity)
                        } else {
                            eprintln!("Failed to parse IntegrityBankRead");
                            Err(SfmError::InvalidCommandStructure)
                        }
                    },
                    SfmCommandCode::IntegrityBankUpdate => {
                        if let Some(bank_update) = SfmIntegrityBankUpdate::parse_with_trailer(cmd.get_trailer()) {
                            self.integrity_bank_update(bank_update)
                        } else {
                            eprintln!("Failed to parse IntegrityBankUpdate");
                            Err(SfmError::InvalidCommandStructure)
                        }
                    },
                    SfmCommandCode::CreateObject => {
                        if let Some(create_object) = SfmCreateObject::parse_with_trailer(cmd.get_trailer()) {
                            self.create_object(create_object)
                        } else {
                            eprintln!("Failed to parse CreateObject");
                            Err(SfmError::InvalidCommandStructure)
                        }
                    },
                    SfmCommandCode::ModifyObject => {
                        let result = SfmModifyObject::parse_with_trailer(cmd.get_trailer());
                        if let Some(modify_object) = result {
                            self.modify_object(modify_object)
                        } else {
                            eprintln!("Failed to parse ModifyObject");
                            Err(SfmError::InvalidCommandStructure)
                        }
                    },
                    SfmCommandCode::CertifyObject => {
                        let result = SfmCertifyObject::parse_with_trailer(cmd.get_trailer());
                        if let Some(certify_object) = result {
                            self.certify_object(certify_object)
                        } else {
                            eprintln!("Failed to parse CertifyObject");
                            Err(SfmError::InvalidCommandStructure)
                        }
                    },
                    SfmCommandCode::AttestQuote => {
                        let result = SfmAttestQuote::parse_with_trailer(cmd.get_trailer());
                        if let Some(attest_quote) = result {
                            self.attest_quote(attest_quote)
                        } else {
                            eprintln!("Failed to parse AttestQuote");
                            Err(SfmError::InvalidCommandStructure)
                        }
                    },
                    SfmCommandCode::EstablishSecureIo => {
                        let result = SfmEstablishSecureIo::parse_with_trailer(cmd.get_trailer());
                        if let Some(establish_secure_io) = result {
                            self.establish_secure_io(establish_secure_io)
                        } else {
                            eprintln!("Failed to parse EstablishSecureIo");
                            Err(SfmError::InvalidCommandStructure)
                        }
                    }
                    x => Err(SfmError::InvalidCommandCode(x.0)),
                };

                // if the message handler returned okay we assumed it sent a response off
                if process_result.is_err() {
                    self.respond_with_error(process_result.err().unwrap())?;
                }
            }
        }

        Ok(())
    }
}

fn main() -> Result<(), Box<dyn Error>> {

    let firmware_fd = env::var("FIRMWARE_FD")
        .expect("fd should be set by parent")
        .parse::<i32>()
        .expect("should represent an integer");

    let stream = unsafe { UnixStream::from_raw_fd(firmware_fd) };

    let mut handler = SfmHandler::new(stream);

    handler.interface()?;

    Ok(())
}
