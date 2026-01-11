use std::sync::Arc;

use sequoia_cert_store::{store::MergeCerts, LazyCert, Store, StoreUpdate};
use sequoia_openpgp::{
    packet::prelude::SignatureBuilder, parse::stream::VerificationHelper, types::SignatureType,
    Fingerprint,
};
use sequoia_wot::{FULLY_TRUSTED, PARTIALLY_TRUSTED};

use crate::{
    api::{db::store::CertDao, PgpApp},
    error::InternalErr,
};

pub enum TrustLevel {
    Ultimate,
    Full,
    Partial,
    Custom(u8),
}

impl TrustLevel {
    fn get_trust(&self) -> u8 {
        let v = match self {
            Self::Ultimate => FULLY_TRUSTED * 2,
            Self::Full => FULLY_TRUSTED,
            Self::Partial => PARTIALLY_TRUSTED,
            Self::Custom(v) => *v as usize,
        };

        std::cmp::min(v, u8::MAX as usize) as u8
    }
}

impl PgpApp {
    pub fn sign_with_trust_level(
        &self,
        signer: &str,
        signee: &str,
        level: u8,
        trust: TrustLevel,
    ) -> anyhow::Result<()> {
        let read = self.pgp.store.read();
        let cert = read.lookup_by_cert_fpr(&Fingerprint::from_hex(signer)?)?;

        let signee = read.lookup_by_cert_fpr(&Fingerprint::from_hex(signee)?)?;

        drop(read);

        let private = self.pgp.db.get_by_fingerprint(signer)?;

        let cert = private.merge(cert.to_cert()?.clone())?;

        let signee = signee.to_cert()?.clone();

        let target = signee.primary_key().component();

        let userid = signee
            .userids()
            .nth(0)
            .map(|v| v.userid())
            .ok_or_else(|| InternalErr::NotFound("userid"))?;

        let mut privkey = cert
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()?
            .into_keypair()?;

        let sig = SignatureBuilder::new(SignatureType::GenericCertification)
            .set_trust_signature(level, trust.get_trust())?
            .set_issuer_fingerprint(cert.fingerprint())?
            .sign_userid_binding(&mut privkey, target, userid)?;

        println!("OLD {}", signee.is_tsk());
        let (sig, _) = signee.insert_packets(sig)?;

        println!("NEW {}", sig.is_tsk());

        // let (sig, _) = signee.merge_public(sig)?;

        self.pgp
            .store
            .read()
            .update_by(Arc::new(LazyCert::from_cert(sig)), &SignMerge)?;

        self.pgp.store.mega_flush()?;

        self.pgp.db.fire_watchers()?;
        //  println!("flush fire watchers");
        Ok(())
    }
}

struct SignMerge;

impl<'a> MergeCerts<'a> for SignMerge {
    fn merge_public<'b>(
        &self,
        new: Arc<LazyCert<'a>>,
        disk: Option<Arc<LazyCert<'b>>>,
    ) -> sequoia_openpgp::Result<Arc<LazyCert<'a>>> {
        match disk {
            None => Ok(new),
            Some(disk) => Ok(Arc::new(LazyCert::from_cert(
                disk.to_cert()?
                    .clone()
                    .merge_public(new.to_cert()?.clone())?,
            ))),
        }
    }
}

pub(crate) struct PgpAppVerifier<'a> {
    pub(crate) fingerprints: Vec<String>,
    app: &'a PgpApp,
}

impl<'a> PgpAppVerifier<'a> {
    pub(crate) fn from_app(app: &'a PgpApp) -> Self {
        Self {
            fingerprints: Vec::new(),
            app,
        }
    }
}

impl<'a> VerificationHelper for &mut PgpAppVerifier<'a> {
    fn check(
        &mut self,
        _: sequoia_openpgp::parse::stream::MessageStructure,
    ) -> sequoia_openpgp::Result<()> {
        Ok(())
    }

    fn get_certs(
        &mut self,
        ids: &[sequoia_openpgp::KeyHandle],
    ) -> sequoia_openpgp::Result<Vec<sequoia_openpgp::Cert>> {
        let mut certs = Vec::with_capacity(ids.len());
        for id in ids {
            let cert = self.app.pgp.store.lookup_by_cert_or_subkey(id)?;
            for cert in cert {
                self.fingerprints.push(cert.fingerprint().to_hex());
                certs.push(cert.to_cert()?.clone());
            }
        }

        // self.fingerprints
        //     .extend(ids.into_iter().map(|v| v.to_owned()));

        Ok(certs)
    }
}

impl VerificationHelper for &PgpApp {
    fn check(
        &mut self,
        _: sequoia_openpgp::parse::stream::MessageStructure,
    ) -> sequoia_openpgp::Result<()> {
        Ok(())
    }

    fn get_certs(
        &mut self,
        ids: &[sequoia_openpgp::KeyHandle],
    ) -> sequoia_openpgp::Result<Vec<sequoia_openpgp::Cert>> {
        let mut certs = Vec::with_capacity(ids.len());
        for id in ids {
            let cert = self.pgp.store.lookup_by_cert_or_subkey(id)?;
            for cert in cert {
                certs.push(cert.to_cert()?.clone());
            }
        }

        Ok(certs)
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use sequoia_cert_store::Store;
    use sequoia_openpgp::KeyHandle;

    use crate::api::{db::store::CertDao, pgp::test_config, PgpApp, PgpAppTrait};
    #[test]
    fn sig_available_after_sign() {
        let app = PgpApp::create(test_config("app")).unwrap();

        let key1 = app
            .generate_key("test1@example.com".to_owned())
            .generate()
            .unwrap();

        let key2 = app
            .generate_key("test2@example.com".to_owned())
            .generate()
            .unwrap();

        let key2test = app
            .pgp
            .get_key_from_fingerprint(&key2.cert.fingerprint)
            .unwrap();

        assert_eq!(key2test.sigs.len(), 0);

        let owned = app
            .all_owned_certs()
            .unwrap()
            .into_iter()
            .filter(|v| v.cert.fingerprint == key2.cert.fingerprint)
            .next()
            .unwrap();

        assert_eq!(owned.sigs.len(), 0);

        app.sign_with_trust_level(
            &key1.cert.fingerprint,
            &key2.cert.fingerprint,
            1,
            super::TrustLevel::Full,
        )
        .unwrap();

        let key2test = app
            .pgp
            .get_key_from_fingerprint(&key2.cert.fingerprint)
            .unwrap();

        let owned = app
            .all_owned_certs()
            .unwrap()
            .into_iter()
            .filter(|v| v.cert.fingerprint == key2.cert.fingerprint)
            .next()
            .unwrap();

        assert_eq!(owned.sigs.len(), 1);

        assert_eq!(key2test.sigs.len(), 1);
    }

    #[test]
    fn sign_wot() {
        let app = PgpApp::create(test_config("app")).unwrap();

        let key1 = app
            .generate_key("test1@example.com".to_owned())
            .generate()
            .unwrap();

        let key2 = app
            .generate_key("test2@example.com".to_owned())
            .generate()
            .unwrap();

        app.sign_with_trust_level(
            &key1.cert.fingerprint,
            &key2.cert.fingerprint,
            1,
            super::TrustLevel::Full,
        )
        .unwrap();

        for key in app
            .pgp
            .read()
            .lookup_by_cert_or_subkey(&KeyHandle::from_str(&key2.cert.fingerprint).unwrap())
            .unwrap()
        {
            let key = app.pgp.get_api_cert(key.to_cert().unwrap()).unwrap();

            assert_eq!(key.sigs.len(), 1);
        }
    }

    #[test]
    fn sign_with_secret() {
        let app = PgpApp::create(test_config("app")).unwrap();

        let key1 = app
            .generate_key("test1@example.com".to_owned())
            .generate()
            .unwrap();

        let key2 = app
            .generate_key("test2@example.com".to_owned())
            .generate()
            .unwrap();

        assert!(key2.has_private());

        app.sign_with_trust_level(
            &key1.cert.fingerprint,
            &key2.cert.fingerprint,
            1,
            super::TrustLevel::Full,
        )
        .unwrap();

        // app.pgp.0 .0.mega_flush().unwrap();

        // let key = app
        //     .pgp
        //     .0
        //      .0
        //     .lookup_by_cert_fpr(&Fingerprint::from_hex(&key2.cert.fingerprint).unwrap())
        //     .unwrap();

        // println!("{key:?}");

        // assert!(key.to_cert().unwrap().is_tsk());

        let db_cert = app
            .pgp
            .db
            .get_by_fingerprint(&key2.cert.fingerprint)
            .unwrap();

        for key in app
            .pgp
            .read()
            .lookup_by_cert_or_subkey(&KeyHandle::from_str(&key2.cert.fingerprint).unwrap())
            .unwrap()
        {
            let key = db_cert.merge(key.to_cert().unwrap().clone()).unwrap();
            let key = app.pgp.get_api_cert(&key).unwrap();
            println!("{key:?}");

            assert!(key.has_private());
        }
    }
}
