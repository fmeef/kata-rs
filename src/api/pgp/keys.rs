use std::sync::Arc;

use sequoia_cert_store::{LazyCert, StoreUpdate};
use sequoia_openpgp::{
    cert::{CertBuilder, CipherSuite},
    packet::Signature,
};

use crate::api::pgp::PgpService;

pub struct PgpKey {
    key: Arc<LazyCert<'static>>,
    revocation: Option<Signature>,
}

impl PgpService {
    pub fn generate_key(&self, user_id: &str) -> anyhow::Result<PgpKey> {
        let (key, revocation) = CertBuilder::new()
            .add_signing_subkey()
            .add_storage_encryption_subkey()
            .add_authentication_subkey()
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_userid(user_id)
            .generate()?;

        let key = Arc::new(LazyCert::from_cert(key));
        self.store.update(key.clone())?;

        Ok(PgpKey {
            key,
            revocation: Some(revocation),
        })
    }

    // pub fn get_all_owned(&self) -> anyhow::Result<Vec<PgpKey>> {

    //     self.store
    // }
}
