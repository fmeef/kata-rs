use sequoia_cert_store::{store::KeyServer, Store, StoreUpdate};
use sequoia_net::KeyServer as Upload;
use sequoia_openpgp::{Cert, Fingerprint, Packet};

use crate::{
    api::{pgp::UserHandle, PgpApp},
    error::Result,
};

impl PgpApp {
    pub fn fill_from_keyserver(&self, fingerprint: &UserHandle, server: &str) -> Result<()> {
        let ks = KeyServer::new(server)?;
        if let Ok(key) = ks.lookup_by_cert_fpr(fingerprint.try_fingerprint()?) {
            self.pgp.store.update(key)?;
        }

        Ok(())
    }

    fn filter_cert_online_sigs(&self, cert: Cert) -> anyhow::Result<Cert> {
        let cert = cert.clone().into_packets().filter(|p| match p {
            Packet::Signature(s) => s
                .issuer_fingerprints()
                .all(|f| self.pgp.db.check_online(&f.to_hex())),

            _ => true,
        });

        let cert = Cert::from_packets(cert)?;
        Ok(cert)
    }

    pub async fn upload_to_keyserver(&self, fingerprint: &UserHandle, server: &str) -> Result<()> {
        let ks = Upload::new(server)?;
        if let Ok(key) = self
            .pgp
            .store
            .lookup_by_cert_fpr(fingerprint.try_fingerprint()?)
        {
            let cert = key.to_cert()?;
            if self.pgp.db.check_online(&cert.fingerprint().to_hex()) {
                let cert = self.filter_cert_online_sigs(cert.clone())?;
                ks.send(&cert).await?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use sequoia_cert_store::{store::KeyServer, Store};
    use sequoia_openpgp::{Fingerprint, Packet};

    use crate::api::{
        pgp::{sign::TrustLevel, test_config, POLICY},
        PgpApp, PgpAppTrait,
    };

    #[test]
    fn test_keyserver() {
        let ks = KeyServer::new("hkps://keys.ballmerlabs.net").unwrap();
        let out = ks
            .lookup_by_cert_fpr(
                &Fingerprint::from_hex("9FCF6558AC4927F1E7A43D80317375B449854036").unwrap(),
            )
            .unwrap();
        assert_eq!(
            ks.fingerprints()
                .find(|p| p.to_hex() == "9FCF6558AC4927F1E7A43D80317375B449854036")
                .unwrap()
                .to_hex(),
            "9FCF6558AC4927F1E7A43D80317375B449854036"
        );

        assert_eq!(
            out.fingerprint().to_hex(),
            "9FCF6558AC4927F1E7A43D80317375B449854036"
        );
    }

    #[test]
    fn upload_online() {
        let test = PgpApp::create(test_config("app")).unwrap();
        let online = test
            .generate_key("online@example.com".to_owned())
            .online(true)
            .generate()
            .unwrap();

        let offline = test
            .generate_key("offline@example.com".to_owned())
            .online(false)
            .generate()
            .unwrap();

        test.sign_with_trust_level(
            &online.cert.fingerprint.name(),
            &offline.cert.fingerprint.name(),
            1,
            TrustLevel::Full,
        )
        .unwrap();

        test.sign_with_trust_level(
            &offline.cert.fingerprint.name(),
            &online.cert.fingerprint.name(),
            1,
            TrustLevel::Full,
        )
        .unwrap();

        let online = test
            .pgp
            .store
            .lookup_by_cert_fpr(&online.cert.fingerprint.try_fingerprint().unwrap())
            .unwrap()
            .to_cert()
            .unwrap()
            .clone();

        let offline = test
            .pgp
            .store
            .lookup_by_cert_fpr(&offline.cert.fingerprint.try_fingerprint().unwrap())
            .unwrap()
            .to_cert()
            .unwrap()
            .clone();

        let offline_fpr = offline.primary_key().key().fingerprint().to_hex();

        let p = online.clone().into_packets().any(|p| {
            println!("{p:?}");
            match p {
                Packet::Signature(s) => s.issuer_fingerprints().any(|f| f.to_hex() == offline_fpr),
                _ => false,
            }
        });

        assert!(p);

        let online_strip = test.filter_cert_online_sigs(online).unwrap();
        let p = online_strip.into_packets().any(|p| {
            println!("{p:?}");
            match p {
                Packet::Signature(s) => s.issuer_fingerprints().any(|f| f.to_hex() == offline_fpr),

                _ => false,
            }
        });

        assert!(!p);
    }
}
