use flutter_rust_bridge::frb;

use sequoia_cert_store::LazyCert;
use sequoia_openpgp::{parse::Parse, Cert};
use sequoia_wot::{store::Store, Depth};

use crate::{
    api::{
        pgp::{PgpServiceTrait, UserHandle},
        PgpApp,
    },
    frb_generated::RustAutoOpaque,
};

#[derive(Debug, Clone, PartialEq, PartialOrd)]
#[frb(opaque)]
pub struct PgpCert {
    pub keyid: String,
    pub fingerprint: UserHandle,
    pub has_private: bool,
    pub online: bool,
}

#[derive(Debug)]
pub struct PgpCertStubSigs {
    pub cert: PgpCert,
    pub ids: Vec<String>,
    pub sigs: Vec<String>,
    pub certifications: Vec<String>,
}

#[derive(Debug, Clone)]
#[frb(opaque)]
pub struct PgpCertWithIds {
    pub cert: PgpCert,
    pub ids: Vec<String>,
    pub sigs: Vec<MaybeCert>,
    pub certifications: Vec<MaybeCert>,
}

#[derive(Debug, Clone)]
#[frb(non_opaque)]
pub enum MaybeCert {
    Full {
        cert: RustAutoOpaque<PgpCertWithIds>,
    },
    Fingerprint {
        fpr: RustAutoOpaque<UserHandle>,
    },
}

impl MaybeCert {
    #[frb(sync)]
    pub fn from_cert(cert: &PgpCertWithIds) -> MaybeCert {
        MaybeCert::Full {
            cert: RustAutoOpaque::new(cert.clone()),
        }
    }

    #[frb(sync)]
    pub fn fingerprint(&self) -> anyhow::Result<UserHandle> {
        match self {
            Self::Fingerprint { fpr } => Ok(fpr.blocking_read().clone()),
            Self::Full { cert } => Ok(cert.blocking_read().cert.fingerprint.clone()),
        }
    }

    #[frb(sync)]
    pub fn maybe_ids(&self) -> Option<Vec<String>> {
        match self {
            Self::Fingerprint { .. } => None,
            Self::Full { cert } => Some(cert.blocking_read().ids.clone()),
        }
    }
}

impl PgpCertStubSigs {
    #[frb(sync)]
    pub fn from_bytes(bytes: Vec<u8>) -> anyhow::Result<Self> {
        let cert = Cert::from_bytes(&bytes)?;
        let newcert = PgpCert {
            keyid: cert.keyid().to_hex(),
            fingerprint: UserHandle::from_fingerprint(
                cert.fingerprint(),
                cert.userids().map(|v| v.userid().to_string()).next(),
            ),
            has_private: cert.is_tsk(),
            online: false,
        };

        Ok(Self {
            cert: newcert,
            ids: cert.userids().map(|v| v.userid().to_string()).collect(),
            sigs: vec![],
            certifications: vec![],
        })
    }

    pub fn from_bytes_sig(bytes: Vec<u8>, store: &PgpApp) -> anyhow::Result<Self> {
        let cert = Cert::from_bytes(&bytes)?;

        //     let valid = cert.with_policy(&POLICY, None)?;

        let newcert = PgpCert {
            keyid: cert.keyid().to_hex(),
            fingerprint: UserHandle::from_fingerprint(
                cert.fingerprint(),
                cert.userids().map(|v| v.userid().to_string()).next(),
            ),
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

impl PgpCertWithIds {
    #[frb(sync)]
    pub fn from_bytes(bytes: Vec<u8>) -> anyhow::Result<Self> {
        let cert = Cert::from_bytes(&bytes)?;
        let newcert = PgpCert {
            keyid: cert.keyid().to_hex(),
            fingerprint: UserHandle::from_fingerprint(
                cert.fingerprint(),
                cert.userids().map(|v| v.userid().to_string()).next(),
            ),
            has_private: cert.is_tsk(),
            online: false,
        };

        Ok(Self {
            cert: newcert,
            ids: cert.userids().map(|v| v.userid().to_string()).collect(),
            sigs: vec![],
            certifications: vec![],
        })
    }

    #[frb(sync)]
    pub fn copy(&self) -> PgpCertWithIds {
        self.clone()
    }

    #[frb(sync)]
    pub fn id_hex(&self) -> String {
        self.cert.fingerprint.fingerprint()
    }

    pub fn from_bytes_sig(bytes: Vec<u8>, store: &PgpApp) -> anyhow::Result<Self> {
        let cert = Cert::from_bytes(&bytes)?;
        let newcert = PgpCert {
            keyid: cert.keyid().to_hex(),
            fingerprint: UserHandle::from_fingerprint(
                cert.fingerprint(),
                cert.userids().map(|v| v.userid().to_string()).next(),
            ),
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
                .filter_map(|v| {
                    UserHandle::from_hex(&v)
                        .map(|v| {
                            store
                                .get_stub_from_fingerprint(&v)
                                .map(|v| MaybeCert::Full {
                                    cert: RustAutoOpaque::new(v),
                                })
                                .unwrap_or_else(|_| MaybeCert::Fingerprint {
                                    fpr: RustAutoOpaque::new(v),
                                })
                        })
                        .ok()
                })
                .collect(),
            certifications: cert
                .user_attributes()
                .flat_map(|v| v.certifications())
                .flat_map(|v| v.issuers())
                .map(|v| v.to_hex())
                .filter_map(|v| {
                    UserHandle::from_hex(&v)
                        .map(|v| {
                            store
                                .get_stub_from_fingerprint(&v)
                                .map(|v| MaybeCert::Full {
                                    cert: RustAutoOpaque::new(v),
                                })
                                .unwrap_or_else(|_| MaybeCert::Fingerprint {
                                    fpr: RustAutoOpaque::new(v),
                                })
                        })
                        .ok()
                })
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
        let comment = cert.userids().map(|v| v.userid().to_string()).next();
        let lazy = LazyCert::from_cert(cert);
        Ok(Self {
            keyid: lazy.keyid().to_hex(),
            fingerprint: UserHandle::from_fingerprint(lazy.fingerprint(), comment),
            has_private: lazy.is_tsk(),
            online: false,
        })
    }

    // pub(crate) fn as_cert(&self) -> anyhow::Result<Cert> {
    //     Ok(Cert::from_bytes(&self.data)?)
    // }
}
