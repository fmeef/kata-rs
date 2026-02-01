use anyhow::anyhow;
use flutter_rust_bridge::frb;
use sequoia_cert_store::{LazyCert, Store, StoreUpdate};
pub use sequoia_openpgp::{
    cert::{CertBuilder, CipherSuite},
    packet::Signature,
    serialize::Marshal,
    Cert,
};
use sequoia_wot::{store::StoreError, Depth};
use std::{
    str::FromStr,
    sync::{Arc, RwLock},
};

use sequoia_openpgp::{packet::UserID, Fingerprint, KeyHandle};

use crate::{
    api::{
        db::{connection::Crud, store::PgpDataCert},
        pgp::{
            cert::{PgpCert, PgpCertWithIds},
            PgpServiceStore, UserHandle,
        },
        PgpAppTrait,
    },
    frb_generated::StreamSink,
};

impl PgpCertWithIds {
    // pub fn revocation_cert(&self) -> anyhow::Result<Option<String>> {
    //     if let Some(ref revoke) = self.revocation {
    //         let mut out = Writer::new(Vec::new(), Kind::Signature)?;
    //         revoke.serialize(&mut out)?;
    //         let out = out.finalize()?;
    //         Ok(Some(String::from_utf8(out)?))
    //     } else {
    //         Ok(None)
    //     }
    // }

    #[frb(sync)]
    pub fn has_private(&self) -> bool {
        self.cert.has_private
    }
}

struct GenerateCertInner {
    email: String,
    name: Option<String>,
    comment: Option<String>,
    online: bool,
}

#[frb(opaque)]
pub struct GenerateCert {
    inner: RwLock<GenerateCertInner>,
    app: Box<dyn PgpAppTrait + Send + Sync>,
}

impl GenerateCert {
    pub(crate) fn new(email: String, app: Box<dyn PgpAppTrait + Send + Sync>) -> Self {
        let inner = GenerateCertInner {
            email,
            name: None,
            comment: None,
            online: false,
        };

        GenerateCert {
            inner: RwLock::new(inner),
            app,
        }
    }

    #[frb(sync)]
    pub fn name(self, name: String) -> GenerateCert {
        self.inner.write().unwrap().name = Some(name);
        self
    }

    #[frb(sync)]
    pub fn online(self, online: bool) -> GenerateCert {
        self.inner.write().unwrap().online = online;
        self
    }

    #[frb(sync)]
    pub fn comment(self, comment: String) -> GenerateCert {
        self.inner.write().unwrap().comment = Some(comment);
        self
    }

    pub fn generate(self) -> anyhow::Result<PgpCertWithIds> {
        let inner = self.inner.read().unwrap();
        let (cert, _) = CertBuilder::new()
            .add_signing_subkey()
            .add_storage_encryption_subkey()
            .add_authentication_subkey()
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_userid(UserID::from_address(
                inner.name.as_deref(),
                inner.comment.as_deref(),
                &inner.email,
            )?)
            .generate()?;

        let newcert = PgpCert {
            keyid: cert.keyid().to_hex(),
            fingerprint: UserHandle::from_fingerprint(cert.fingerprint()),
            has_private: cert.is_tsk(),
            online: inner.online,
        };

        drop(inner);

        let out = PgpCertWithIds {
            cert: newcert,
            ids: cert.userids().map(|v| v.userid().to_string()).collect(),
            sigs: self
                .app
                .certifications_of(&cert.fingerprint().to_hex(), None)
                .unwrap_or_default()
                .into_iter()
                .flat_map(|v| {
                    v.certifications
                        .into_iter()
                        .flat_map(|(_, v)| v.into_iter().map(|v| v.issuer))
                })
                .collect(),
            certifications: cert
                .user_attributes()
                .flat_map(|v| v.certifications())
                .flat_map(|v| v.issuers())
                .map(|v| v.to_hex())
                .collect(),
        };

        let tsk = cert.as_tsk();

        let tsk = PgpDataCert::as_tsk(out.cert.clone(), tsk)?;

        self.app.update_cert(Arc::new(LazyCert::from_cert(cert)))?;

        tsk.insert(&self.app.get_db())?;

        self.app.mega_flush()?;

        Ok(out)
    }
}

impl<T> PgpServiceStore<T>
where
    T: Send + Sync + sequoia_cert_store::Store<'static> + StoreUpdate<'static>,
{
    pub(crate) fn get_api_cert(&self, cert: &Cert) -> anyhow::Result<PgpCertWithIds> {
        let fingerprint = cert.fingerprint().to_hex();
        let online = self.db.check_online(&fingerprint);
        let newcert = PgpCert {
            keyid: cert.keyid().to_hex(),
            fingerprint: UserHandle::from_fingerprint(cert.fingerprint()),
            has_private: cert.is_tsk(),
            online,
        };

        Ok(PgpCertWithIds {
            cert: newcert,
            ids: cert.userids().map(|v| v.userid().to_string()).collect(),
            sigs: sequoia_wot::store::Store::certifications_of(
                &self.store.read(),
                &cert.fingerprint(),
                Depth::Unconstrained,
            )?
            .iter()
            .flat_map(|v| {
                v.certifications()
                    .flat_map(|(_, v)| v.iter().map(|v| v.issuer().fingerprint().to_hex()))
            })
            .collect(),
            certifications: cert
                .user_attributes()
                .flat_map(|v| v.certifications())
                .flat_map(|v| v.issuers())
                .map(|v| v.to_hex())
                .collect(),
        })
    }

    pub fn iter_certs(&self, sink: StreamSink<PgpCertWithIds>) -> anyhow::Result<()> {
        for key in self.store.read().certs() {
            match key.to_cert().map(|k| self.get_api_cert(k)).flatten() {
                Ok(key) => {
                    sink.add(key).map_err(|e| anyhow!(e))?;
                }
                Err(err) => log::error!("iter_certs_search skip failed {err}"),
            }
        }
        Ok(())
    }

    pub fn get_key_from_fingerprint(
        &self,
        fingerprint: &UserHandle,
    ) -> anyhow::Result<PgpCertWithIds> {
        let kh = fingerprint.try_keyhandle()?;
        let cert = self.store.read().lookup_by_cert_or_subkey(kh)?;

        match cert.len() {
            1 => Ok(self.get_api_cert(cert[0].to_cert()?)?),
            0 => Err(anyhow!(StoreError::NotFound(kh.clone()))),
            _ => Err(anyhow!(StoreError::NotFound(kh.clone()))), //TODO: custom err
        }
    }

    pub fn iter_fingerprints(&self, sink: StreamSink<String>) -> anyhow::Result<()> {
        for key in self.store.read().certs() {
            sink.add(key.fingerprint().to_hex())
                .map_err(|e| anyhow!(e))?;
        }
        Ok(())
    }

    pub fn iter_certs_search(
        &self,
        sink: StreamSink<PgpCertWithIds>,
        pattern: &str,
    ) -> anyhow::Result<()> {
        for key in self.store.read().grep_userid(pattern)? {
            match key.to_cert().map(|k| self.get_api_cert(k)).flatten() {
                Ok(key) => {
                    sink.add(key).map_err(|e| anyhow!(e))?;
                }
                Err(err) => log::error!("iter_certs_search skip failed {err}"),
            }
        }
        Ok(())
    }

    pub fn iter_certs_search_keyid(
        &self,
        sink: StreamSink<PgpCertWithIds>,
        pattern: &str,
    ) -> anyhow::Result<()> {
        for key in self
            .store
            .read()
            .lookup_by_cert_or_subkey(&KeyHandle::from_str(pattern)?)?
        {
            match key.to_cert().map(|k| self.get_api_cert(k)).flatten() {
                Ok(key) => {
                    sink.add(key).map_err(|e| anyhow!(e))?;
                }
                Err(err) => log::error!("iter_certs_search skip failed {err}"),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use sequoia_cert_store::Store;
    use sequoia_openpgp::Fingerprint;

    use crate::api::{db::store::CertDao, pgp::test_config, PgpApp, PgpAppTrait};

    #[test]
    fn generate_insert() {
        let test = PgpApp::create(test_config("app")).unwrap();
        let _ = test
            .generate_key("test@example.com".to_owned())
            .generate()
            .unwrap();
    }

    #[test]
    fn generate_fetch() {
        let test = PgpApp::create(test_config("app")).unwrap();
        let k = test
            .generate_key("test@example.com".to_owned())
            .generate()
            .unwrap();
        let new = test
            .pgp
            .store
            .read()
            .lookup_by_cert_fpr(&k.cert.fingerprint.try_fingerprint().unwrap())
            .unwrap();

        let private = test
            .pgp
            .db
            .get_by_fingerprint(&k.cert.fingerprint.name())
            .unwrap();

        let new = private.merge(new.to_cert().unwrap().clone()).unwrap();

        assert_eq!(new.fingerprint().to_hex(), k.cert.fingerprint.name());
        assert!(new.is_tsk());
    }
}
