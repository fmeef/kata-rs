use flutter_rust_bridge::frb;

use sequoia_cert_store::{LazyCert, StoreUpdate};
use sequoia_openpgp::{parse::Parse, Cert};
use sequoia_wot::{store::Store, Depth};

use crate::api::{pgp::PgpServiceStore, PgpApp, PgpAppTrait};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[frb(non_opaque)]
pub struct PgpCert {
    pub keyid: String,
    pub fingerprint: String,
    pub has_private: bool,
    pub online: bool,
}

#[derive(Debug)]
pub struct PgpCertWithIds {
    pub cert: PgpCert,
    pub ids: Vec<String>,
    pub sigs: Vec<String>,
    pub certifications: Vec<String>,
}

impl PgpCertWithIds {
    #[frb(sync)]
    pub fn from_bytes(bytes: Vec<u8>) -> anyhow::Result<Self> {
        let cert = Cert::from_bytes(&bytes)?;
        let newcert = PgpCert {
            keyid: cert.keyid().to_hex(),
            fingerprint: cert.fingerprint().to_hex(),
            has_private: cert.is_tsk(),
            online: false,
        };

        Ok(Self {
            cert: newcert,
            ids: cert.userids().map(|v| v.userid().to_string()).collect(),
            sigs: vec![],
            certifications: cert
                .user_attributes()
                .flat_map(|v| v.certifications())
                .flat_map(|v| v.issuers())
                .map(|v| v.to_hex())
                .collect(),
        })
    }

    pub(crate) fn from_bytes_sig(bytes: Vec<u8>, store: &PgpApp) -> anyhow::Result<Self> {
        let cert = Cert::from_bytes(&bytes)?;

        //     let valid = cert.with_policy(&POLICY, None)?;

        let newcert = PgpCert {
            keyid: cert.keyid().to_hex(),
            fingerprint: cert.fingerprint().to_hex(),
            has_private: cert.is_tsk(),
            online: false,
        };

        Ok(Self {
            cert: newcert,
            ids: cert.userids().map(|v| v.userid().to_string()).collect(),
            sigs: store
                .pgp
                .store
                .read()
                .certifications_of(&cert.fingerprint(), Depth::Unconstrained)?
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
}

impl PgpCert {
    // #[frb(sync)]
    // pub fn get_keyid<'a>(&'a self) -> &'a str {
    //     &self.keyid
    // }

    // #[frb(sync)]
    // pub fn get_fingerprint<'a>(&'a self) -> &'a str {
    //     &self.fingerprint
    // }

    // #[frb(sync)]
    // pub fn owned(&self) -> bool {
    //     self.has_private
    // }

    #[allow(dead_code)]
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> anyhow::Result<Self> {
        let cert = Cert::from_bytes(&bytes)?;
        let lazy = LazyCert::from_cert(cert);
        Ok(Self {
            keyid: lazy.keyid().to_hex(),
            fingerprint: lazy.fingerprint().to_hex(),
            has_private: lazy.is_tsk(),
            online: false,
        })
    }

    // pub(crate) fn as_cert(&self) -> anyhow::Result<Cert> {
    //     Ok(Cert::from_bytes(&self.data)?)
    // }
}
