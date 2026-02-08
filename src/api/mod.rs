pub mod db;
pub mod image;
pub mod pgp;
pub mod ser;

use crate::api::pgp::UserHandle;
use flutter_rust_bridge::frb;
use lazy_static::lazy_static;
pub use sequoia_cert_store::{LazyCert, Store, StoreUpdate};
use sequoia_openpgp::{Cert, Fingerprint};
use sequoia_wot::Roots;
pub use std::path::PathBuf;
use std::{str::FromStr, sync::Arc};

#[cfg(test)]
use crate::api::pgp::PgpServiceTest;

pub use crate::api::{
    db::{connection::SqliteDb, migrations::run_migrations},
    pgp::{wot::network::StoreNetwork, PgpService},
};
use crate::api::{
    db::{
        connection::Watcher,
        store::{CertDao, OnlyFingerprint},
        CertStoreTrait,
    },
    pgp::{cert::PgpCertWithIds, keys::GenerateCert, wot::network::CertNetwork, PgpServiceTrait},
};

pub use sequoia_openpgp::packet::UserID;

lazy_static! {
    static ref LOGGER: () = init_logging();
}

pub fn init_logging() {
    env_logger::init();
}

#[frb(non_opaque)]
pub struct Config {
    pub keystore_path: PathBuf,
    pub db_path: PathBuf,
}

impl Config {
    #[frb(sync)]
    pub fn new(keystore_path: &str, db_path: &str) -> anyhow::Result<Self> {
        Ok(Self {
            keystore_path: PathBuf::from_str(keystore_path)?,
            db_path: PathBuf::from_str(db_path)?,
        })
    }
}

#[derive(Clone)]
#[frb(opaque)]
pub struct PgpApp {
    pub(crate) pgp: PgpService,
}

#[cfg(test)]
#[derive(Clone)]
pub struct PgpAppTest {
    pub(crate) pgp: PgpServiceTest,
}

pub trait PgpAppTrait: PgpServiceTrait + CertStoreTrait {
    #[frb(sync)]
    fn get_watcher(&self) -> Watcher;

    #[frb(sync)]
    fn get_db(&self) -> SqliteDb;

    fn update_cert(&self, cert: Arc<LazyCert<'static>>) -> anyhow::Result<()>;

    fn mega_flush(&self) -> anyhow::Result<()>;

    fn all_owned_certs(&self) -> anyhow::Result<Vec<PgpCertWithIds>>;

    #[frb(sync)]
    fn generate_key(&self, email: String) -> GenerateCert;

    fn delete_private_key(&self, fingerprint: &UserHandle) -> anyhow::Result<()>;

    fn delete_cert(&self, fingerprint: UserHandle) -> anyhow::Result<()>;

    fn get_cert_by_role(&self, role: &str) -> anyhow::Result<Option<PgpCertWithIds>>;

    fn update_role(&self, fingerprint: &UserHandle, role: &str) -> anyhow::Result<()>;
}

impl PgpAppTrait for PgpApp {
    #[frb(sync)]
    fn get_watcher(&self) -> Watcher {
        self.pgp.db.get_watcher()
    }

    #[frb(sync)]
    fn get_db(&self) -> SqliteDb {
        self.pgp.db.clone()
    }

    fn mega_flush(&self) -> anyhow::Result<()> {
        self.pgp.store.mega_flush()
    }

    fn update_cert(&self, cert: Arc<LazyCert<'static>>) -> anyhow::Result<()> {
        self.pgp.store.update(cert)?;

        Ok(())
    }

    fn delete_cert(&self, fingerprint: UserHandle) -> anyhow::Result<()> {
        self.pgp
            .store
            .write()
            .delete_fingerprint(fingerprint.try_fingerprint_owned()?)?;

        self.pgp.db.fire_watchers()?;

        Ok(())
    }

    #[frb(sync)]
    fn generate_key(&self, email: String) -> GenerateCert {
        GenerateCert::new(email, Box::new(self.clone()))
    }

    fn all_owned_certs(&self) -> anyhow::Result<Vec<PgpCertWithIds>> {
        let out = self
            .pgp
            .db
            .all_owned_certs()?
            .into_iter()
            .flat_map(|v| match UserHandle::from_hex(&v.fingerprint) {
                Ok(fp) => self.pgp.get_key_from_fingerprint(&fp).ok().map(|mut v| {
                    v.cert.has_private = true;
                    v
                }),
                Err(_) => None,
            })
            .map(|mut v| {
                v.cert.online = self.pgp.db.check_online(&v.cert.fingerprint.name());
                v
            });

        Ok(out.collect())
    }

    fn delete_private_key(&self, fingerprint: &UserHandle) -> anyhow::Result<()> {
        let mut write = self.pgp.store.write();
        self.pgp
            .db
            .delete_by_fingerprint(&fingerprint.try_fingerprint()?.to_hex())?;

        write.flush()?;
        Ok(())
    }

    fn get_cert_by_role(&self, role: &str) -> anyhow::Result<Option<PgpCertWithIds>> {
        match self.pgp.db.get_fingerprint_for_role(role)? {
            Some(OnlyFingerprint { fingerprint }) => self
                .get_key_from_fingerprint(&UserHandle::from_hex(&fingerprint)?)
                .map(|mut v| {
                    v.cert.has_private = true;
                    v
                })
                .map(Some),
            None => Ok(None),
        }
    }

    fn update_role(&self, fingerprint: &UserHandle, role: &str) -> anyhow::Result<()> {
        self.pgp.db.clear_role(role)?;
        self.pgp
            .db
            .update_role(&fingerprint.try_fingerprint()?.to_hex(), role)?;
        Ok(())
    }
}

#[cfg(test)]
impl PgpAppTrait for PgpAppTest {
    fn get_watcher(&self) -> Watcher {
        self.pgp.db.get_watcher()
    }

    fn get_db(&self) -> SqliteDb {
        self.pgp.db.clone()
    }

    fn mega_flush(&self) -> anyhow::Result<()> {
        Ok(())
    }

    fn delete_cert(&self, _: UserHandle) -> anyhow::Result<()> {
        Ok(())
    }

    fn all_owned_certs(&self) -> anyhow::Result<Vec<PgpCertWithIds>> {
        let out =
            self.pgp.db.all_owned_certs()?.into_iter().flat_map(|v| {
                match UserHandle::from_hex(&v.fingerprint) {
                    Ok(fp) => self.pgp.get_key_from_fingerprint(&fp).ok(),
                    Err(_) => None,
                }
            });

        Ok(out.collect())
    }

    fn delete_private_key(&self, _: &UserHandle) -> anyhow::Result<()> {
        Ok(())
    }

    fn update_cert(&self, _: Arc<LazyCert<'static>>) -> anyhow::Result<()> {
        Ok(())
    }

    fn get_cert_by_role(&self, role: &str) -> anyhow::Result<Option<PgpCertWithIds>> {
        match self.pgp.db.get_fingerprint_for_role(role)? {
            Some(OnlyFingerprint { fingerprint }) => self
                .get_key_from_fingerprint(&UserHandle::from_hex(&fingerprint)?)
                .map(Some),
            None => Ok(None),
        }
    }

    fn update_role(&self, fingerprint: &UserHandle, role: &str) -> anyhow::Result<()> {
        self.pgp.db.clear_role(role)?;
        self.pgp
            .db
            .update_role(&fingerprint.try_fingerprint()?.to_hex(), role)?;
        Ok(())
    }

    #[frb(sync)]
    fn generate_key(&self, email: String) -> GenerateCert {
        GenerateCert::new(email, Box::new(self.clone()))
    }
}

#[cfg(test)]
impl PgpServiceTrait for PgpAppTest {
    fn export_armor(&self) -> anyhow::Result<String> {
        self.pgp.export_armor()
    }

    fn export_file(&self, file: &str) -> anyhow::Result<()> {
        self.pgp.export_file(file)
    }

    fn get_key_from_fingerprint(
        &self,
        fingerprint: &UserHandle,
    ) -> anyhow::Result<pgp::cert::PgpCertWithIds> {
        self.pgp.get_key_from_fingerprint(fingerprint)
    }

    fn import_certs(&self, import: &dyn pgp::import::PgpImport) -> anyhow::Result<()> {
        self.pgp.import_certs(import)
    }

    fn get_stub_from_fingerprint(
        &self,
        fingerprint: &UserHandle,
    ) -> anyhow::Result<PgpCertWithIds> {
        self.pgp.get_stub_from_fingerprint(fingerprint)
    }

    fn iter_certs(
        &self,
        sink: crate::frb_generated::StreamSink<pgp::cert::PgpCertWithIds>,
    ) -> anyhow::Result<()> {
        self.pgp.iter_certs(sink)
    }

    fn iter_certs_search(
        &self,
        sink: crate::frb_generated::StreamSink<pgp::cert::PgpCertWithIds>,
        pattern: &str,
    ) -> anyhow::Result<()> {
        self.pgp.iter_certs_search(sink, pattern)
    }

    fn iter_certs_search_keyid(
        &self,
        sink: crate::frb_generated::StreamSink<pgp::cert::PgpCertWithIds>,
        pattern: &str,
    ) -> anyhow::Result<()> {
        self.pgp.iter_certs_search_keyid(sink, pattern)
    }

    fn iter_fingerprints(
        &self,
        sink: crate::frb_generated::StreamSink<String>,
    ) -> anyhow::Result<()> {
        self.pgp.iter_fingerprints(sink)
    }
}

impl PgpServiceTrait for PgpApp {
    fn export_armor(&self) -> anyhow::Result<String> {
        self.pgp.export_armor()
    }

    fn export_file(&self, file: &str) -> anyhow::Result<()> {
        self.pgp.export_file(file)
    }

    fn get_key_from_fingerprint(
        &self,
        fingerprint: &UserHandle,
    ) -> anyhow::Result<pgp::cert::PgpCertWithIds> {
        self.pgp.get_key_from_fingerprint(fingerprint)
    }

    fn get_stub_from_fingerprint(
        &self,
        fingerprint: &UserHandle,
    ) -> anyhow::Result<PgpCertWithIds> {
        self.pgp.get_stub_from_fingerprint(fingerprint)
    }

    fn import_certs(&self, import: &dyn pgp::import::PgpImport) -> anyhow::Result<()> {
        self.pgp.import_certs(import)
    }

    fn iter_certs(
        &self,
        sink: crate::frb_generated::StreamSink<pgp::cert::PgpCertWithIds>,
    ) -> anyhow::Result<()> {
        self.pgp.iter_certs(sink)
    }

    fn iter_certs_search(
        &self,
        sink: crate::frb_generated::StreamSink<pgp::cert::PgpCertWithIds>,
        pattern: &str,
    ) -> anyhow::Result<()> {
        self.pgp.iter_certs_search(sink, pattern)
    }

    fn iter_certs_search_keyid(
        &self,
        sink: crate::frb_generated::StreamSink<pgp::cert::PgpCertWithIds>,
        pattern: &str,
    ) -> anyhow::Result<()> {
        self.pgp.iter_certs_search_keyid(sink, pattern)
    }

    fn iter_fingerprints(
        &self,
        sink: crate::frb_generated::StreamSink<String>,
    ) -> anyhow::Result<()> {
        self.pgp.iter_fingerprints(sink)
    }
}

#[cfg(test)]
impl CertStoreTrait for PgpAppTest {
    fn certifications_of(
        &self,
        target: &str,
        min_depth: Option<usize>,
    ) -> anyhow::Result<Vec<db::CertificationSet>> {
        self.pgp.read().certifications_of(target, min_depth)
    }

    fn certified_userids(&self) -> Vec<(String, UserID)> {
        self.pgp.read().certified_userids()
    }

    fn certified_userids_of(&self, fpr: &str) -> anyhow::Result<Vec<UserID>> {
        self.pgp.read().certified_userids_of(fpr)
    }

    fn get_fingerprints(&self) -> Vec<String> {
        self.pgp.read().get_fingerprints()
    }

    fn lookup_synopses(&self, kh: &db::KeyHandle) -> anyhow::Result<Vec<db::CertSynopsis>> {
        self.pgp.read().lookup_synopses(kh)
    }

    fn lookup_synopses_by_email(&self, email: &str) -> Vec<(String, UserID)> {
        self.pgp.read().lookup_synopses_by_email(email)
    }

    fn lookup_synopses_by_userid(&self, userid: UserID) -> Vec<String> {
        self.pgp.read().lookup_synopses_by_userid(userid)
    }

    fn lookup_synopsis_by_fpr(&self, fingerprint: &UserHandle) -> anyhow::Result<db::CertSynopsis> {
        self.pgp.read().lookup_synopsis_by_fpr(fingerprint)
    }

    fn synopses(&self) -> Vec<db::CertSynopsis> {
        self.pgp.read().synopses()
    }

    fn third_party_certifications_of(&self, fpr: &str) -> anyhow::Result<Vec<db::Certification>> {
        self.pgp.read().third_party_certifications_of(fpr)
    }
}

impl CertStoreTrait for PgpApp {
    fn certifications_of(
        &self,
        target: &str,
        min_depth: Option<usize>,
    ) -> anyhow::Result<Vec<db::CertificationSet>> {
        self.pgp.store.certifications_of(target, min_depth)
    }

    fn certified_userids(&self) -> Vec<(String, UserID)> {
        self.pgp.store.certified_userids()
    }

    fn certified_userids_of(&self, fpr: &str) -> anyhow::Result<Vec<UserID>> {
        self.pgp.store.certified_userids_of(fpr)
    }

    fn get_fingerprints(&self) -> Vec<String> {
        self.pgp.store.get_fingerprints()
    }

    fn lookup_synopses(&self, kh: &db::KeyHandle) -> anyhow::Result<Vec<db::CertSynopsis>> {
        self.pgp.store.lookup_synopses(kh)
    }

    fn lookup_synopses_by_email(&self, email: &str) -> Vec<(String, UserID)> {
        self.pgp.store.lookup_synopses_by_email(email)
    }

    fn lookup_synopses_by_userid(&self, userid: UserID) -> Vec<String> {
        self.pgp.store.lookup_synopses_by_userid(userid)
    }

    fn lookup_synopsis_by_fpr(&self, fingerprint: &UserHandle) -> anyhow::Result<db::CertSynopsis> {
        self.pgp.store.lookup_synopsis_by_fpr(fingerprint)
    }

    fn synopses(&self) -> Vec<db::CertSynopsis> {
        self.pgp.store.synopses()
    }

    fn third_party_certifications_of(&self, fpr: &str) -> anyhow::Result<Vec<db::Certification>> {
        self.pgp.store.third_party_certifications_of(fpr)
    }
}

#[cfg(test)]
impl PgpAppTest {
    #[cfg(test)]
    pub fn create_in_memory() -> anyhow::Result<Self> {
        use crate::api::pgp::PgpServiceTest;

        let db = SqliteDb::new_in_memory()?;
        run_migrations(&db)?;
        Ok(Self {
            pgp: PgpServiceTest::new_in_memory()?,
        })
    }
}

impl PgpApp {
    pub fn create(config: Config) -> anyhow::Result<Self> {
        let db = SqliteDb::new(&config.db_path.to_string_lossy())?;
        run_migrations(&db)?;
        let pgp = PgpService::new(&config.keystore_path.to_string_lossy(), db.clone())?;

        Ok(Self { pgp })
    }

    #[frb(sync)]
    pub fn network<R: Into<Roots>>(&self, roots: R) -> anyhow::Result<StoreNetwork> {
        CertNetwork::from_store(self.pgp.store.clone(), roots)
    }

    pub(crate) fn private_cert(&self, fingerprint: &UserHandle) -> anyhow::Result<Cert> {
        let cert = self
            .pgp
            .store
            .read()
            .lookup_by_cert_fpr(fingerprint.try_fingerprint()?)?;

        let private = self
            .pgp
            .db
            .get_by_fingerprint(&fingerprint.try_fingerprint()?.to_hex())?;
        Ok(private.merge(cert.to_cert()?.clone())?)
    }

    #[frb(sync)]
    pub fn network_from_fingerprints(
        &self,
        fingerprints: Vec<String>,
    ) -> anyhow::Result<StoreNetwork> {
        self.network(Roots::new(
            fingerprints
                .into_iter()
                .filter_map(|v| Fingerprint::from_hex(&v).ok()),
        ))
    }

    #[frb(sync)]
    pub fn unrooted_network(&self) -> anyhow::Result<StoreNetwork> {
        CertNetwork::from_store_unrooted(self.pgp.store.clone())
    }

    // pub fn network_builder(&self) -> anyhow::Result<CertNetworkBuilder> {
    //     CertNetworkBuilder::new(&self.pgp.store)
    // }
}
