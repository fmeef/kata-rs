use sequoia_openpgp::{
    serialize::stream::{Compressor, Message, Signer},
    types::CompressionAlgorithm,
};
use serde::{Deserialize, Serialize};

use crate::{
    api::{
        pgp::{UserHandle, POLICY},
        PgpApp,
    },
    error::InternalErr,
};

#[derive(Serialize, Deserialize)]
pub struct Circle {
    pub members: Vec<UserHandle>,
    pub author: UserHandle,
    pub id: UserHandle,
}

impl PgpApp {
    pub fn create_circle(&self, author: &UserHandle, keys: Vec<UserHandle>) -> anyhow::Result<()> {
        let cert = self.private_cert(author)?;
        let mut out = Vec::new();
        {
            let private_kp = cert
                .keys()
                .secret()
                .with_policy(&POLICY, None)
                .supported()
                .alive()
                .revoked(false)
                .for_signing()
                .nth(0)
                .ok_or_else(|| InternalErr::NotFound("subkey"))?
                .key()
                .clone()
                .into_keypair()?;

            let message = Message::new(&mut out);

            let signer = Signer::new(message, private_kp)?.build()?;

            let signer = Compressor::new(signer)
                .algo(CompressionAlgorithm::BZip2)
                .build()?;

            Ok(())
        }
    }
}
