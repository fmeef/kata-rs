use anyhow::anyhow;
use flutter_rust_bridge::frb;
use serde::{de::Visitor, ser::SerializeMap, Deserialize, Serialize};
#[cfg(test)]
use std::path::PathBuf;

use sequoia_cert_store::{store::Pep, LazyCert, Store, StoreUpdate};
use sequoia_openpgp::{policy::StandardPolicy, Fingerprint, KeyHandle};
use serde::de::Error;
use std::{hash::Hash, str::FromStr, sync::Arc};

#[cfg(test)]
use crate::api::Config;
use crate::{
    api::{
        db::{
            connection::{Crud, OnConflict},
            store::CircleData,
        },
        pgp::{
            cert::PgpCertWithIds,
            circles::{CircleEntry, CircleHandle, CircleLike, CircleType},
            import::PgpImport,
            mut_store::MutStore,
        },
        SqliteDb,
    },
    error::InternalErr,
    frb_generated::{RustAutoOpaque, StreamSink},
};

#[cfg(test)]
use crate::api::pgp::mut_store::ReadStore;

pub mod cert;
pub mod circles;
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
#[derive(Clone, PartialEq, PartialOrd)]
pub enum UserHandle {
    KeyHandle(KeyHandle, Option<String>),
    RawBytes(Vec<u8>),
}

impl std::fmt::Debug for UserHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UserHandle(")?;
        f.write_str(&self.name())?;
        f.write_str(")")
    }
}

impl Hash for UserHandle {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            Self::KeyHandle(kh, name) => {
                state.write(kh.as_bytes());
                name.hash(state);
            }
            Self::RawBytes(b) => state.write(&b),
        }
    }
}

impl Ord for UserHandle {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.name().cmp(&other.name())
    }
}

impl Eq for UserHandle {}

impl Serialize for UserHandle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(1))?;
        let key = match self {
            Self::KeyHandle(_, _) => "key_handle",
            Self::RawBytes(_) => "raw",
        };
        map.serialize_key(key)?;
        map.serialize_value(&self.name())?;

        map.end()
    }
}

struct UserHandleVisitor;

impl<'de> Visitor<'de> for UserHandleVisitor {
    type Value = UserHandle;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("Expecting a UserHandle")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if let Some((key, value)) = map.next_entry::<String, String>()? {
            match key.as_str() {
                "key_handle" => {
                    return Ok(UserHandle::from_hex(&value)
                        .map_err(|_| A::Error::custom("UserHandle invalid hex"))?)
                }
                "raw" => {
                    return Ok(UserHandle::from_raw_hex(&value)
                        .map_err(|_| A::Error::custom("UserHandle invalid raw hex"))?)
                }
                _ => return Err(A::Error::custom("invalid keyhandle type")),
            };
        }

        Err(A::Error::custom("no map key/value"))
    }
}

impl<'de> Deserialize<'de> for UserHandle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(UserHandleVisitor)
    }
}

impl CircleLike for UserHandle {
    #[frb(sync)]
    fn get_id(&self) -> Vec<u8> {
        self.as_bytes().to_owned()
    }

    #[frb(sync)]
    fn get_id_userhandle(&self) -> UserHandle {
        self.clone()
    }

    #[frb(sync)]
    fn get_member(&self, id: CircleHandle) -> anyhow::Result<Option<circles::CircleEntry>> {
        let test = CircleHandle {
            id: self.name(),
            circle_type: CircleType::User,
        };
        let res = if id == test {
            Some(circles::CircleEntry {
                id,
                content: None,
                tag: None,
            })
        } else {
            None
        };

        Ok(res)
    }

    fn iter_members(&self, sink: StreamSink<circles::CircleEntry>) {
        sink.add(circles::CircleEntry {
            id: CircleHandle {
                id: self.name(),
                circle_type: CircleType::User,
            },
            content: None,
            tag: None,
        })
        .unwrap();
    }

    fn verify(&self) -> anyhow::Result<bool> {
        Ok(true)
    }

    #[frb(sync)]
    fn get_type(&self) -> circles::CircleType {
        CircleType::User
    }

    fn insert(&self, db: &SqliteDb) -> anyhow::Result<()> {
        self.to_db(db)
    }

    #[frb(sync)]
    fn get_members(&self) -> Vec<circles::CircleEntry> {
        vec![CircleEntry::from_circle_or(circles::CircleOr::User(
            RustAutoOpaque::new(self.clone()),
        ))]
    }

    fn validate(&self) -> anyhow::Result<bool> {
        Ok(true)
    }
}

impl UserHandle {
    #[frb(sync)]
    pub fn from_hex(hex: &str) -> anyhow::Result<Self> {
        Ok(Self::KeyHandle(KeyHandle::from_str(hex)?, None))
    }

    #[frb(sync)]
    pub fn handle(&self) -> CircleHandle {
        CircleHandle {
            id: self.name(),
            circle_type: CircleType::User,
        }
    }

    #[frb(sync)]
    pub fn comment(&self) -> Option<String> {
        match self {
            Self::RawBytes(_) => None,
            Self::KeyHandle(_, comment) => comment.clone(),
        }
    }

    pub(crate) fn from_fingerprint(fingerprint: Fingerprint, name: Option<String>) -> Self {
        Self::KeyHandle(KeyHandle::Fingerprint(fingerprint), name)
    }

    #[frb(sync)]
    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    pub fn set_name(&mut self, name: String) {
        if let Self::KeyHandle(_, n) = self {
            *n = Some(name);
        }
    }

    fn from_raw_hex(hex: &str) -> crate::error::Result<Self> {
        Ok(Self::RawBytes(hex::decode(hex)?))
    }

    #[frb(sync)]
    pub fn name(&self) -> String {
        match self {
            Self::KeyHandle(kh, _) => kh.to_hex(),
            Self::RawBytes(bytes) => hex::encode(bytes),
        }
    }

    pub(crate) fn as_bytes(&self) -> &'_ [u8] {
        match self {
            Self::KeyHandle(kh, _) => kh.as_bytes(),
            Self::RawBytes(bytes) => bytes,
        }
    }

    pub fn to_db(&self, db: &SqliteDb) -> anyhow::Result<()> {
        let data = CircleData {
            id: self.name(),
            circle_type: "user".to_owned(),
            author: Some(self.name()),
            sig: None,
        };

        data.insert_on_conflict_custom(db, OnConflict::Update, vec!["id", "circle_type"])?;

        Ok(())
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        match self {
            Self::KeyHandle(kh, _) => kh.as_bytes().to_owned(),
            Self::RawBytes(bytes) => bytes,
        }
    }

    pub(crate) fn try_keyhandle(&self) -> anyhow::Result<&'_ KeyHandle> {
        match self {
            Self::KeyHandle(kh, _) => Ok(kh),
            Self::RawBytes(_) => Err(anyhow!(InternalErr::NotRepr("KeyHandle"))),
        }
    }

    pub(crate) fn try_fingerprint(&self) -> anyhow::Result<&'_ Fingerprint> {
        match self {
            Self::KeyHandle(kh, _) => match kh {
                KeyHandle::Fingerprint(fp) => Ok(fp),
                KeyHandle::KeyID(_) => Err(anyhow!(InternalErr::FingerprintRequired)),
            },
            Self::RawBytes(_) => Err(anyhow!(InternalErr::NotRepr("Fingerprint"))),
        }
    }

    pub(crate) fn try_fingerprint_owned(self) -> anyhow::Result<Fingerprint> {
        match self {
            Self::KeyHandle(kh, _) => match kh {
                KeyHandle::Fingerprint(fp) => Ok(fp),
                KeyHandle::KeyID(_) => Err(anyhow!(InternalErr::FingerprintRequired)),
            },
            Self::RawBytes(_) => Err(anyhow!(InternalErr::NotRepr("Fingerprint"))),
        }
    }
}

pub trait PgpServiceTrait {
    fn import_certs(&self, import: &dyn PgpImport) -> anyhow::Result<()>;
    fn export_file(&self, file: &str) -> anyhow::Result<()>;
    fn export_armor(&self) -> anyhow::Result<String>;
    fn iter_certs(&self, sink: StreamSink<PgpCertWithIds>) -> anyhow::Result<()>;
    fn get_key_from_fingerprint(&self, fingerprint: &UserHandle) -> anyhow::Result<PgpCertWithIds>;
    fn get_key_or(&self, fingerprint: &UserHandle) -> Option<PgpCertWithIds> {
        self.get_key_from_fingerprint(fingerprint).ok()
    }
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
        pgp::{test_keystore, PgpService, UserHandle},
        SqliteDb,
    };

    #[test]
    fn new_pgp_service() {
        let _ =
            PgpService::new(&test_keystore("test"), SqliteDb::new_in_memory().unwrap()).unwrap();
    }

    #[test]
    fn userhandle_serde() {
        let v = UserHandle::from_hex("9FCF6558AC4927F1E7A43D80317375B449854036").unwrap();
        let s = serde_json::to_string(&v).unwrap();
        let o: UserHandle = serde_json::from_str(&s).unwrap();

        assert_eq!(v.name(), o.name())
    }
}
