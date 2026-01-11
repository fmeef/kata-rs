use anyhow::Result;
pub use sequoia_openpgp::packet::UserID;
use sequoia_openpgp::Fingerprint;
use sequoia_wot::store::Store;
use sequoia_wot::{Depth, RevocationStatus};
pub mod connection;
pub mod entities;
pub mod migrations;
pub mod store;

pub enum KeyHandle {
    KeyId(String),
    Fingerprint(String),
}

impl KeyHandle {
    fn handle(&self) -> anyhow::Result<sequoia_openpgp::KeyHandle> {
        let res = match self {
            Self::Fingerprint(f) => {
                sequoia_openpgp::KeyHandle::Fingerprint(Fingerprint::from_hex(f)?)
            }
            Self::KeyId(k) => {
                sequoia_openpgp::KeyHandle::KeyID(sequoia_openpgp::KeyID::from_hex(k)?)
            }
        };
        Ok(res)
    }
}

pub struct Certification {
    pub issuer: String,
    pub target: String,
}

pub struct CertificationSet {
    pub issuer: String,
    pub target: String,
    pub certifications: Vec<(Option<String>, Vec<Certification>)>,
}

pub struct CertSynopsis {
    pub fingerprint: String,
    pub keyid: String,
    pub key_handle: KeyHandle,
    pub revoked: bool,
    pub userids: Vec<String>,
}

impl From<&sequoia_wot::Certification> for Certification {
    fn from(value: &sequoia_wot::Certification) -> Self {
        Self {
            issuer: value.issuer().fingerprint().to_hex(),
            target: value.target().fingerprint().to_hex(),
        }
    }
}

impl From<&sequoia_wot::CertificationSet> for CertificationSet {
    fn from(value: &sequoia_wot::CertificationSet) -> Self {
        Self {
            issuer: value.issuer().fingerprint().to_hex(),
            target: value.target().fingerprint().to_hex(),
            certifications: value
                .certifications()
                .into_iter()
                .map(|(id, cert)| {
                    (
                        id.map(|i| i.to_string()),
                        cert.into_iter().map(|c| c.into()).collect(),
                    )
                })
                .collect(),
        }
    }
}

impl From<sequoia_wot::CertSynopsis> for CertSynopsis {
    fn from(value: sequoia_wot::CertSynopsis) -> Self {
        Self {
            fingerprint: value.fingerprint().to_hex(),
            keyid: value.keyid().to_hex(),
            key_handle: match value.key_handle() {
                sequoia_openpgp::KeyHandle::Fingerprint(fpr) => {
                    KeyHandle::Fingerprint(fpr.to_hex())
                }
                sequoia_openpgp::KeyHandle::KeyID(fpr) => KeyHandle::KeyId(fpr.to_hex()),
            },
            revoked: !matches!(
                value.revocation_status(),
                RevocationStatus::NotAsFarAsWeKnow
            ),
            userids: value.userids().map(|v| v.to_string()).collect(),
        }
    }
}

pub trait CertStoreTrait {
    // Required methods
    // fn reference_time(&self) -> SystemTime;
    fn get_fingerprints(&self) -> Vec<String>;
    fn lookup_synopses(&self, kh: &KeyHandle) -> Result<Vec<CertSynopsis>>;
    fn certifications_of(
        &self,
        target: &str,
        min_depth: Option<usize>,
    ) -> Result<Vec<CertificationSet>>;

    // Provided methods
    fn synopses(&self) -> Vec<CertSynopsis>;
    fn lookup_synopsis_by_fpr(&self, fingerprint: &str) -> Result<CertSynopsis>;
    fn third_party_certifications_of(&self, fpr: &str) -> Result<Vec<Certification>>;
    fn certified_userids_of(&self, fpr: &str) -> Result<Vec<UserID>>;
    fn certified_userids(&self) -> Vec<(String, UserID)>;
    fn lookup_synopses_by_userid(&self, userid: UserID) -> Vec<String>;
    fn lookup_synopses_by_email(&self, email: &str) -> Vec<(String, UserID)>;
}

impl<T> CertStoreTrait for T
where
    T: Store,
{
    fn certifications_of(
        &self,
        target: &str,
        min_depth: Option<usize>,
    ) -> Result<Vec<CertificationSet>> {
        Ok(Store::certifications_of(
            self,
            &Fingerprint::from_hex(target)?,
            match min_depth {
                None => Depth::Unconstrained,
                Some(v) => Depth::Limit(v),
            },
        )?
        .iter()
        .map(|v| v.into())
        .collect())
    }

    fn certified_userids(&self) -> Vec<(String, UserID)> {
        Store::certified_userids(self)
            .into_iter()
            .map(|(f, v)| (f.to_hex(), v))
            .collect()
    }

    fn certified_userids_of(&self, fpr: &str) -> Result<Vec<UserID>> {
        Ok(Store::certified_userids_of(
            self,
            &Fingerprint::from_hex(fpr)?,
        ))
    }

    fn get_fingerprints(&self) -> Vec<String> {
        Store::iter_fingerprints(self).map(|v| v.to_hex()).collect()
    }

    fn lookup_synopses(&self, kh: &KeyHandle) -> Result<Vec<CertSynopsis>> {
        Ok(Store::lookup_synopses(self, &kh.handle()?)?
            .into_iter()
            .map(|v| v.into())
            .collect())
    }

    fn lookup_synopses_by_email(&self, email: &str) -> Vec<(String, UserID)> {
        Store::lookup_synopses_by_email(self, email)
            .into_iter()
            .map(|(v, u)| (v.to_hex(), u.into()))
            .collect()
    }

    fn lookup_synopses_by_userid(&self, userid: UserID) -> Vec<String> {
        Store::lookup_synopses_by_userid(self, userid)
            .iter()
            .map(|v| v.to_hex())
            .collect()
    }

    fn lookup_synopsis_by_fpr(&self, fingerprint: &str) -> Result<CertSynopsis> {
        Ok(Store::lookup_synopsis_by_fpr(self, &Fingerprint::from_hex(fingerprint)?)?.into())
    }

    // fn reference_time(&self) -> SystemTime {
    //     Store::reference_time(self)
    // }

    fn synopses(&self) -> Vec<CertSynopsis> {
        Store::synopses(self).map(|v| v.into()).collect()
    }

    fn third_party_certifications_of(&self, fpr: &str) -> Result<Vec<Certification>> {
        let res = Store::third_party_certifications_of(self, &Fingerprint::from_hex(fpr)?)
            .iter()
            .map(|v| Certification {
                issuer: v.issuer().fingerprint().to_hex(),
                target: v.target().fingerprint().to_hex(),
            })
            .collect();

        Ok(res)
    }
}
