use http::Uri;
use std::fmt;

use serde::Serialize;

#[cfg(feature = "tpm_fapi")]
use helium_crypto::tpm::keypair_fapi::KeypairFapi;
#[cfg(feature = "tpm_esys")]
use helium_crypto::tpm::keypair_esys::KeypairHandle;

use helium_crypto::{Keypair, KeyTag, KeyType, Network, Sign, Verify};

use crate::{
    device::test::{self, TestResult},
    Result,
};

#[derive(Debug)]
pub struct Device {
    /// TPM key path
    pub key_identifier: String,
    pub key_access_mode: String,
}

impl Device {
    /// Parses an tpm device url of the form `tpm://fapi/<key_path>` or `tpm://handle/<hex_handle>`,
    /// where <key_path> is the path to TPM KEY
    /// and <hex_handle> is the persistent handle of the key in hex format.
    pub fn from_url(url: &Uri) -> Result<Self> {
        Ok(Self {
            key_identifier: (&url.path()[1..]).parse()?,
            key_access_mode: url.host().unwrap().parse()?
        })
    }

    pub fn get_info(&self) -> Result<Info> {
        Ok(Info {
            key_identifier: self.key_identifier.clone(),
        })
    }

    pub fn get_keypair(&self, create: bool) -> Result<Keypair> {
        if create {
            panic!("not supported")
        }
        let keypair = match self.key_access_mode.as_str() {
            #[cfg(feature = "tpm_fapi")]
            "fapi" => KeypairFapi::from_key_path(Network::MainNet, self.key_identifier.as_str()).map(helium_crypto::Keypair::from),
            #[cfg(feature = "tpm_esys")]
            "handle" => KeypairHandle::from_key_handle(Network::MainNet, u32::from_str_radix(&self.key_identifier[2..], 16).unwrap()).map(helium_crypto::Keypair::from),
            _ => { Err(helium_crypto::Error::invalid_keytype_str("unknown tpm key access type")) }
        }?;

        Ok(keypair)
    }

    pub fn provision(&self) -> Result<Keypair> {
        panic!("not supported")
    }

    pub fn get_config(&self) -> Result<Config> {
        Ok(Config {
            key_identifier: self.key_identifier.clone(),
            key_access_mode: self.key_access_mode.clone(),
        })
    }

    pub fn get_tests(&self) -> Vec<Test> {
        vec![
            Test::MinerKey(self.key_identifier.clone(), self.key_access_mode.clone()),
            Test::Sign(self.key_identifier.clone(), self.key_access_mode.clone()),
            Test::Ecdh(self.key_identifier.clone(), self.key_access_mode.clone()),
        ]
    }
}

#[derive(Debug, Serialize)]
pub struct Info {
    pub key_identifier: String,
}

#[derive(Debug, Serialize)]
pub struct Config {
    pub key_identifier: String,
    pub key_access_mode: String,
}

#[derive(Debug)]
pub enum Test {
    MinerKey(String, String),
    Sign(String, String),
    Ecdh(String, String),
}

impl fmt::Display for Test {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MinerKey(key_identifier, _key_access_mode) => f.write_fmt(format_args!("miner_key({key_identifier})")),
            Self::Sign(key_identifier, _key_access_mode) => f.write_fmt(format_args!("sign({key_identifier})")),
            Self::Ecdh(key_identifier, _key_access_mode) => f.write_fmt(format_args!("ecdh({key_identifier})")),
        }
    }
}

impl Test {
    pub fn run(&self) -> TestResult {
        match self {
            Self::MinerKey(key_identifier, key_access_mode) => check_miner_key(key_identifier, key_access_mode),
            Self::Sign(key_identifier, key_access_mode) => check_sign(key_identifier, key_access_mode),
            Self::Ecdh(key_identifier, key_access_mode) => check_ecdh(key_identifier, key_access_mode),
        }
    }
}

fn check_miner_key(key_identifier: &str, key_access_mode: &str) -> TestResult {
    let keypair = match key_access_mode {
        #[cfg(feature = "tpm_fapi")]
        "fapi" => KeypairFapi::from_key_path(Network::MainNet, key_identifier).map(helium_crypto::Keypair::from),
        #[cfg(feature = "tpm_esys")]
        "handle" => KeypairHandle::from_key_handle(Network::MainNet, u32::from_str_radix(&key_identifier[2..], 16).unwrap()).map(helium_crypto::Keypair::from),
        _ => { Err(helium_crypto::Error::invalid_keytype_str("unknown tpm key access type")) }
    }?;
    test::pass(keypair.public_key()).into()
}

fn check_sign(key_identifier: &str, key_access_mode: &str) -> TestResult {
    const DATA: &[u8] = b"hello world";
    let keypair = match key_access_mode {
        #[cfg(feature = "tpm_fapi")]
        "fapi" => KeypairFapi::from_key_path(Network::MainNet, key_identifier).map(helium_crypto::Keypair::from),
        #[cfg(feature = "tpm_esys")]
        "handle" => KeypairHandle::from_key_handle(Network::MainNet, u32::from_str_radix(&key_identifier[2..], 16).unwrap()).map(helium_crypto::Keypair::from),
        _ => { Err(helium_crypto::Error::invalid_keytype_str("unknown tpm key access type")) }
    }?;
    let signature = keypair.sign(DATA)?;
    keypair.public_key().verify(DATA, &signature)?;
    test::pass("ok").into()
}

fn check_ecdh(key_identifier: &str, key_access_mode: &str) -> TestResult {
    use rand::rngs::OsRng;
    let keypair = match key_access_mode {
        #[cfg(feature = "tpm_fapi")]
        "fapi" => KeypairFapi::from_key_path(Network::MainNet, key_identifier).map(helium_crypto::Keypair::from),
        #[cfg(feature = "tpm_esys")]
        "handle" => KeypairHandle::from_key_handle(Network::MainNet, u32::from_str_radix(&key_identifier[2..], 16).unwrap()).map(helium_crypto::Keypair::from),
        _ => { Err(helium_crypto::Error::invalid_keytype_str("unknown tpm key access type")) }
    }?;
    let other_keypair = Keypair::generate(
        KeyTag {
            network: Network::MainNet,
            key_type: KeyType::EccCompact,
        },
        &mut OsRng,
    );
    let ecc_shared_secret = keypair.ecdh(other_keypair.public_key())?;
    let other_shared_secret = other_keypair.ecdh(keypair.public_key())?;

    if ecc_shared_secret.raw_secret_bytes() != other_shared_secret.raw_secret_bytes() {
        return test::expected(
            format!("{:#02x}", ecc_shared_secret.raw_secret_bytes()),
            format!("{:#02x}", other_shared_secret.raw_secret_bytes()),
        )
        .into();
    }
    test::pass("ok").into()
}
