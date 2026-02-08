use anyhow::anyhow;
use flutter_rust_bridge::frb;
#[cfg(test)]
use std::path::PathBuf;

use sequoia_cert_store::{store::Pep, LazyCert, Store, StoreUpdate};
use sequoia_openpgp::{policy::StandardPolicy, Fingerprint, KeyHandle};
use std::{str::FromStr, sync::Arc};

#[cfg(test)]
use crate::api::Config;
use crate::{
    api::{
        pgp::{cert::PgpCertWithIds, import::PgpImport, mut_store::MutStore},
        SqliteDb,
    },
    error::InternalErr,
    frb_generated::StreamSink,
};

#[cfg(test)]
use crate::api::pgp::mut_store::ReadStore;

pub mod cert;
pub mod export;
pub mod fingerprint;
pub mod import;
pub mod keys;
pub mod keyserver;
pub(crate) mod mut_store;
pub mod sharedstore;
pub mod sign;
pub mod wot;

pub static POLICY: StandardPolicy = StandardPolicy::new();

pub trait Verifier {
    fn verify(&self, data: Vec<u8>) -> bool;
}

#[frb(opaque)]
#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub enum UserHandle {
    KeyHandle(KeyHandle),
}

impl UserHandle {
    #[frb(sync)]
    pub fn from_hex(hex: &str) -> anyhow::Result<Self> {
        Ok(Self::KeyHandle(KeyHandle::from_str(hex)?))
    }

    pub(crate) fn from_fingerprint(fingerprint: Fingerprint) -> Self {
        Self::KeyHandle(KeyHandle::Fingerprint(fingerprint))
    }

    #[frb(sync)]
    pub fn name(&self) -> String {
        match self {
            Self::KeyHandle(kh) => kh.to_hex(),
        }
    }

    pub(crate) fn as_bytes(&self) -> &'_ [u8] {
        match self {
            Self::KeyHandle(kh) => kh.as_bytes(),
        }
    }

    pub(crate) fn keyhandle(&self) -> Option<&'_ KeyHandle> {
        match self {
            Self::KeyHandle(kh) => Some(kh),
        }
    }

    pub(crate) fn try_keyhandle(&self) -> anyhow::Result<&'_ KeyHandle> {
        match self {
            Self::KeyHandle(kh) => Ok(kh),
        }
    }

    pub(crate) fn try_fingerprint(&self) -> anyhow::Result<&'_ Fingerprint> {
        match self {
            Self::KeyHandle(kh) => match kh {
                KeyHandle::Fingerprint(fp) => Ok(fp),
                KeyHandle::KeyID(_) => Err(anyhow!(InternalErr::FingerprintRequired)),
            },
        }
    }

    pub(crate) fn try_fingerprint_owned(self) -> anyhow::Result<Fingerprint> {
        match self {
            Self::KeyHandle(kh) => match kh {
                KeyHandle::Fingerprint(fp) => Ok(fp),
                KeyHandle::KeyID(_) => Err(anyhow!(InternalErr::FingerprintRequired)),
            },
        }
    }
}

pub trait PgpServiceTrait {
    fn import_certs(&self, import: &dyn PgpImport) -> anyhow::Result<()>;
    fn export_file(&self, file: &str) -> anyhow::Result<()>;
    fn export_armor(&self) -> anyhow::Result<String>;
    fn iter_certs(&self, sink: StreamSink<PgpCertWithIds>) -> anyhow::Result<()>;
    fn get_key_from_fingerprint(&self, fingerprint: &UserHandle) -> anyhow::Result<PgpCertWithIds>;
    fn get_stub_from_fingerprint(&self, fingerprint: &UserHandle)
        -> anyhow::Result<PgpCertWithIds>;
    fn iter_fingerprints(&self, sink: StreamSink<String>) -> anyhow::Result<()>;
    fn iter_certs_search(
        &self,
        sink: StreamSink<PgpCertWithIds>,
        pattern: &str,
    ) -> anyhow::Result<()>;
    fn iter_certs_search_keyid(
        &self,
        sink: StreamSink<PgpCertWithIds>,
        pattern: &str,
    ) -> anyhow::Result<()>;
}

#[frb(opaque)]
pub struct PgpServiceStore<T: Send + Sync + StoreUpdate<'static> + Store<'static>> {
    pub(crate) store: MutStore<'static, T>,
    pub(crate) db: SqliteDb,
}

impl<T> Clone for PgpServiceStore<T>
where
    T: Send + Sync + StoreUpdate<'static> + Store<'static>,
{
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            db: self.db.clone(),
        }
    }
}

pub type PgpService = PgpServiceStore<Pep>;

#[cfg(test)]
impl PgpServiceTest {
    pub(crate) fn read(&self) -> ReadStore<'_, 'static, Pep> {
        self.store.read()
    }
}

// #[frb]
// impl PgpServiceTrait for PgpService {
//     fn export_armor(&self) -> anyhow::Result<String> {
//         self.0.export_armor()
//     }

//     fn export_file(&self, file: &str) -> anyhow::Result<()> {
//         self.0.export_file(file)
//     }

//     fn get_key_from_fingerprint(&self, fingerprint: &str) -> anyhow::Result<PgpCertWithIds> {
//         self.0.get_key_from_fingerprint(fingerprint)
//     }

//     fn import_certs(&self, import: &dyn PgpImport) -> anyhow::Result<()> {
//         self.0.import_certs(import)
//     }

//     fn iter_certs(&self, sink: StreamSink<PgpCertWithIds>) -> anyhow::Result<()> {
//         self.0.iter_certs(sink)
//     }

//     fn iter_certs_search(
//         &self,
//         sink: StreamSink<PgpCertWithIds>,
//         pattern: &str,
//     ) -> anyhow::Result<()> {
//         self.0.iter_certs_search(sink, pattern)
//     }

//     fn iter_certs_search_keyid(
//         &self,
//         sink: StreamSink<PgpCertWithIds>,
//         pattern: &str,
//     ) -> anyhow::Result<()> {
//         self.0.iter_certs_search_keyid(sink, pattern)
//     }

//     fn iter_fingerprints(&self, sink: StreamSink<String>) -> anyhow::Result<()> {
//         self.0.iter_fingerprints(sink)
//     }
// }

#[cfg(test)]
pub type PgpServiceTest = PgpServiceStore<Pep>;

#[cfg(test)]
impl PgpServiceTrait for PgpServiceTest {
    fn export_armor(&self) -> anyhow::Result<String> {
        self.export_armor()
    }

    fn export_file(&self, file: &str) -> anyhow::Result<()> {
        self.export_file(file)
    }

    fn get_key_from_fingerprint(&self, fingerprint: &UserHandle) -> anyhow::Result<PgpCertWithIds> {
        self.get_key_from_fingerprint(fingerprint)
    }

    fn get_stub_from_fingerprint(
        &self,
        fingerprint: &UserHandle,
    ) -> anyhow::Result<PgpCertWithIds> {
        self.get_stub_from_fingerprint(fingerprint)
    }

    fn import_certs(&self, import: &dyn PgpImport) -> anyhow::Result<()> {
        self.import_certs(import)
    }

    fn iter_certs(&self, sink: StreamSink<PgpCertWithIds>) -> anyhow::Result<()> {
        self.iter_certs(sink)
    }

    fn iter_certs_search(
        &self,
        sink: StreamSink<PgpCertWithIds>,
        pattern: &str,
    ) -> anyhow::Result<()> {
        self.iter_certs_search(sink, pattern)
    }

    fn iter_certs_search_keyid(
        &self,
        sink: StreamSink<PgpCertWithIds>,
        pattern: &str,
    ) -> anyhow::Result<()> {
        self.iter_certs_search_keyid(sink, pattern)
    }

    fn iter_fingerprints(&self, sink: StreamSink<String>) -> anyhow::Result<()> {
        self.iter_fingerprints(sink)
    }
}

#[cfg(test)]
impl PgpServiceTest {
    pub fn new_in_memory() -> anyhow::Result<Self> {
        use sequoia_wot::store::CertStore;

        let store = Pep::empty()?;
        let store = CertStore::from_store(store, &POLICY, None);
        Ok(Self {
            store: MutStore::new_in_memory(store),
            db: SqliteDb::new_in_memory()?,
        })
    }
}

impl PgpService {
    pub fn new(store_dir: &str, db: SqliteDb) -> anyhow::Result<Self> {
        Ok(Self {
            store: MutStore::new(store_dir, db.clone())?,
            db,
        })
    }
}

impl<T> PgpServiceStore<T>
where
    T: Send + Sync + Store<'static> + StoreUpdate<'static> + 'static,
{
    pub fn import_certs(&self, import: &dyn PgpImport) -> anyhow::Result<()> {
        let packets = import.get_packets()?;

        for packet in packets.into_iter() {
            self.store
                .read()
                .update(Arc::new(LazyCert::from_cert(packet?)))?;
        }

        Ok(())
    }
}

#[cfg(test)]
pub fn test_keystore(namespace: &str) -> String {
    use std::str::FromStr;

    use uuid::Uuid;

    let out = std::env!("OUT_DIR");
    let mut out = PathBuf::from_str(out).unwrap();

    let uuid = Uuid::new_v4();
    out.push(format!("test_keystore{uuid}"));
    out.push(namespace);
    std::fs::create_dir_all(&out).ok();

    out.to_string_lossy().into_owned()
}

#[cfg(test)]
pub fn test_config(namespace: &str) -> Config {
    use std::{fs::remove_dir_all, str::FromStr};

    let ksdir = test_keystore(namespace);
    let dbpath = PathBuf::from_str(&ksdir).unwrap();
    println!("dbpath {dbpath:?}");
    remove_dir_all(&dbpath).unwrap();
    std::fs::create_dir(&dbpath).ok();
    Config::new(
        &dbpath.as_path().to_string_lossy(),
        &dbpath.join("test.sqlite").to_string_lossy(),
    )
    .unwrap()
}

#[cfg(test)]
mod test {
    use crate::api::{
        pgp::{test_keystore, PgpService},
        SqliteDb,
    };

    #[test]
    fn new_pgp_service() {
        let _ =
            PgpService::new(&test_keystore("test"), SqliteDb::new_in_memory().unwrap()).unwrap();
    }
}
