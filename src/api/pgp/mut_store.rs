use std::{
    path::PathBuf,
    str::FromStr,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use sequoia_cert_store::{store::Pep, StoreUpdate};
use sequoia_openpgp::Fingerprint;
use sequoia_wot::store::CertStore;

use crate::{
    api::{pgp::POLICY, SqliteDb},
    error::Result,
};
pub(crate) struct MutStore<'c, T>
where
    T: sequoia_cert_store::Store<'c> + Send + Sync,
{
    store: Arc<RwLock<sequoia_wot::store::CertStore<'c, 'c, T>>>,
    sqlite_db: SqliteDb,
    store_dir: String,
}

impl<'c, T> Clone for MutStore<'c, T>
where
    T: sequoia_cert_store::Store<'c> + Send + Sync,
{
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
            store_dir: self.store_dir.clone(),
            sqlite_db: self.sqlite_db.clone(),
        }
    }
}

pub(crate) struct WriteStore<'a, 'c, T>(
    RwLockWriteGuard<'a, sequoia_wot::store::CertStore<'c, 'c, T>>,
)
where
    T: sequoia_cert_store::Store<'c>;

pub(crate) struct ReadStore<'a, 'c, T>(
    RwLockReadGuard<'a, sequoia_wot::store::CertStore<'c, 'c, T>>,
)
where
    T: sequoia_cert_store::Store<'c>;

impl<'c, T> sequoia_cert_store::store::Store<'c> for MutStore<'c, T>
where
    T: sequoia_cert_store::Store<'c> + Send + Sync,
{
    fn certs<'b>(&'b self) -> Box<dyn Iterator<Item = Arc<sequoia_cert_store::LazyCert<'c>>> + 'b>
    where
        'c: 'b,
    {
        Box::new(
            self.read()
                .certs()
                .into_iter()
                .collect::<Vec<_>>()
                .into_iter(),
        )
    }

    fn fingerprints<'b>(&'b self) -> Box<dyn Iterator<Item = Fingerprint> + 'b> {
        Box::new(
            self.read()
                .fingerprints()
                .into_iter()
                .collect::<Vec<_>>()
                .into_iter(),
        )
    }

    fn grep_email(
        &self,
        pattern: &str,
    ) -> sequoia_openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'c>>>> {
        self.read().grep_email(pattern)
    }

    fn grep_userid(
        &self,
        pattern: &str,
    ) -> sequoia_openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'c>>>> {
        self.read().grep_userid(pattern)
    }

    fn lookup_by_cert(
        &self,
        kh: &sequoia_openpgp::KeyHandle,
    ) -> sequoia_openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'c>>>> {
        self.read().lookup_by_cert(kh)
    }

    fn lookup_by_cert_fpr(
        &self,
        fingerprint: &Fingerprint,
    ) -> sequoia_openpgp::Result<Arc<sequoia_cert_store::LazyCert<'c>>> {
        self.read().lookup_by_cert_fpr(fingerprint)
    }

    fn lookup_by_cert_or_subkey(
        &self,
        kh: &sequoia_openpgp::KeyHandle,
    ) -> sequoia_openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'c>>>> {
        self.read().lookup_by_cert_or_subkey(kh)
    }

    fn lookup_by_email(
        &self,
        email: &str,
    ) -> sequoia_openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'c>>>> {
        self.read().lookup_by_email(email)
    }

    fn lookup_by_email_domain(
        &self,
        domain: &str,
    ) -> sequoia_openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'c>>>> {
        self.read().lookup_by_email_domain(domain)
    }

    fn lookup_by_userid(
        &self,
        userid: &sequoia_openpgp::packet::UserID,
    ) -> sequoia_openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'c>>>> {
        self.read().lookup_by_userid(userid)
    }

    fn prefetch_all(&self) {
        self.read().prefetch_all();
    }

    fn prefetch_some(&self, certs: &[sequoia_openpgp::KeyHandle]) {
        self.read().prefetch_some(certs);
    }

    fn select_userid(
        &self,
        query: &sequoia_cert_store::store::UserIDQueryParams,
        pattern: &str,
    ) -> sequoia_openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'c>>>> {
        self.read().select_userid(query, pattern)
    }
}
impl<'c, T> sequoia_wot::store::Store for MutStore<'c, T>
where
    T: sequoia_cert_store::Store<'c> + Send + Sync,
{
    fn certifications_of(
        &self,
        target: &sequoia_openpgp::Fingerprint,
        min_depth: sequoia_wot::Depth,
    ) -> sequoia_openpgp::Result<Arc<Vec<sequoia_wot::CertificationSet>>> {
        self.read().certifications_of(target, min_depth)
    }

    fn certified_userids(
        &self,
    ) -> Vec<(
        sequoia_openpgp::Fingerprint,
        sequoia_openpgp::packet::UserID,
    )> {
        self.read().certified_userids()
    }

    fn certified_userids_of(
        &self,
        fpr: &sequoia_openpgp::Fingerprint,
    ) -> Vec<sequoia_openpgp::packet::UserID> {
        self.read().certified_userids_of(fpr)
    }

    fn iter_fingerprints<'a>(
        &'a self,
    ) -> Box<dyn Iterator<Item = sequoia_openpgp::Fingerprint> + 'a> {
        Box::new(
            self.read()
                .iter_fingerprints()
                .into_iter()
                .collect::<Vec<Fingerprint>>()
                .into_iter(),
        )
    }

    fn lookup_synopses(
        &self,
        kh: &sequoia_openpgp::KeyHandle,
    ) -> sequoia_openpgp::Result<Vec<sequoia_wot::CertSynopsis>> {
        self.read().lookup_synopses(kh)
    }

    fn lookup_synopses_by_email(
        &self,
        email: &str,
    ) -> Vec<(
        sequoia_openpgp::Fingerprint,
        sequoia_openpgp::packet::UserID,
    )> {
        self.read().lookup_synopses_by_email(email)
    }

    fn lookup_synopses_by_userid(
        &self,
        userid: sequoia_openpgp::packet::UserID,
    ) -> Vec<sequoia_openpgp::Fingerprint> {
        self.read().lookup_synopses_by_userid(userid)
    }

    fn lookup_synopsis_by_fpr(
        &self,
        fingerprint: &sequoia_openpgp::Fingerprint,
    ) -> sequoia_openpgp::Result<sequoia_wot::CertSynopsis> {
        self.read().lookup_synopsis_by_fpr(fingerprint)
    }

    fn reference_time(&self) -> std::time::SystemTime {
        self.read().reference_time()
    }

    fn synopses<'a>(&'a self) -> Box<dyn Iterator<Item = sequoia_wot::CertSynopsis> + 'a> {
        Box::new(
            self.read()
                .synopses()
                .into_iter()
                .collect::<Vec<sequoia_wot::CertSynopsis>>()
                .into_iter(),
        )
    }

    fn third_party_certifications_of(
        &self,
        fpr: &sequoia_openpgp::Fingerprint,
    ) -> Vec<sequoia_wot::Certification> {
        self.read().third_party_certifications_of(fpr)
    }
}

impl<'b, 'c, T> sequoia_wot::store::Store for ReadStore<'b, 'c, T>
where
    T: sequoia_cert_store::Store<'c> + Send + Sync,
{
    fn certifications_of(
        &self,
        target: &sequoia_openpgp::Fingerprint,
        min_depth: sequoia_wot::Depth,
    ) -> sequoia_openpgp::Result<Arc<Vec<sequoia_wot::CertificationSet>>> {
        self.0.certifications_of(target, min_depth)
    }

    fn certified_userids(
        &self,
    ) -> Vec<(
        sequoia_openpgp::Fingerprint,
        sequoia_openpgp::packet::UserID,
    )> {
        self.0.certified_userids()
    }

    fn certified_userids_of(
        &self,
        fpr: &sequoia_openpgp::Fingerprint,
    ) -> Vec<sequoia_openpgp::packet::UserID> {
        self.0.certified_userids_of(fpr)
    }

    fn iter_fingerprints<'a>(
        &'a self,
    ) -> Box<dyn Iterator<Item = sequoia_openpgp::Fingerprint> + 'a> {
        self.0.iter_fingerprints()
    }

    fn lookup_synopses(
        &self,
        kh: &sequoia_openpgp::KeyHandle,
    ) -> sequoia_openpgp::Result<Vec<sequoia_wot::CertSynopsis>> {
        self.0.lookup_synopses(kh)
    }

    fn lookup_synopses_by_email(
        &self,
        email: &str,
    ) -> Vec<(
        sequoia_openpgp::Fingerprint,
        sequoia_openpgp::packet::UserID,
    )> {
        self.0.lookup_synopses_by_email(email)
    }

    fn lookup_synopses_by_userid(
        &self,
        userid: sequoia_openpgp::packet::UserID,
    ) -> Vec<sequoia_openpgp::Fingerprint> {
        self.0.lookup_synopses_by_userid(userid)
    }

    fn lookup_synopsis_by_fpr(
        &self,
        fingerprint: &sequoia_openpgp::Fingerprint,
    ) -> sequoia_openpgp::Result<sequoia_wot::CertSynopsis> {
        self.0.lookup_synopsis_by_fpr(fingerprint)
    }

    fn reference_time(&self) -> std::time::SystemTime {
        self.0.reference_time()
    }

    fn synopses<'a>(&'a self) -> Box<dyn Iterator<Item = sequoia_wot::CertSynopsis> + 'a> {
        self.0.synopses()
    }
    fn third_party_certifications_of(
        &self,
        fpr: &sequoia_openpgp::Fingerprint,
    ) -> Vec<sequoia_wot::Certification> {
        self.0.third_party_certifications_of(fpr)
    }
}

impl<'c> MutStore<'c, Pep> {
    pub(crate) fn new(store_dir: &str, db: SqliteDb) -> anyhow::Result<Self> {
        //let store = sequoia_cert_store::CertStore::open(&PathBuf::from_str(store_dir)?)?;
        let store = Pep::open(Some(&PathBuf::from_str(store_dir)?))?;
        //store.add_backend(Box::new(db.clone()), AccessMode::Always);
        let store = CertStore::from_store(store, &POLICY, None);
        Ok(MutStore {
            store: Arc::new(RwLock::new(store)),
            sqlite_db: db,
            store_dir: store_dir.to_owned(),
        })
    }

    pub(crate) fn mega_flush(&self) -> anyhow::Result<()> {
        let mut o = self.store.write().unwrap();
        let store = Pep::open(Some(&PathBuf::from_str(&self.store_dir)?))?;
        // store.add_backend(Box::new(self.sqlite_db.clone()), AccessMode::Always);
        let store = CertStore::from_store(store, &POLICY, None);

        *o = store;
        Ok(())
    }
}

impl<'c, T> StoreUpdate<'c> for MutStore<'c, T>
where
    T: sequoia_cert_store::Store<'c> + sequoia_cert_store::StoreUpdate<'c> + Send + Sync,
{
    fn update(&self, cert: Arc<sequoia_cert_store::LazyCert<'c>>) -> sequoia_openpgp::Result<()> {
        self.read().update(cert)
    }

    fn update_by(
        &self,
        cert: Arc<sequoia_cert_store::LazyCert<'c>>,
        merge_strategy: &dyn sequoia_cert_store::store::MergeCerts<'c>,
    ) -> sequoia_openpgp::Result<Arc<sequoia_cert_store::LazyCert<'c>>> {
        self.read().update_by(cert, merge_strategy)
    }
}

impl<'c, T> MutStore<'c, T>
where
    T: sequoia_cert_store::Store<'c> + Send + Sync,
{
    #[cfg(test)]
    pub(crate) fn new_in_memory(store: CertStore<'c, 'c, T>) -> Self {
        Self {
            store: Arc::new(RwLock::new(store)),
            sqlite_db: SqliteDb::new_in_memory().unwrap(),
            store_dir: "".to_owned(),
        }
    }

    pub(crate) fn read(&self) -> ReadStore<'_, 'c, T> {
        ReadStore(self.store.read().unwrap())
    }

    pub(crate) fn write(&self) -> WriteStore<'_, 'c, T> {
        WriteStore(self.store.write().unwrap())
    }
}

impl<'a, 'c, T> StoreUpdate<'c> for WriteStore<'a, 'c, T>
where
    T: sequoia_cert_store::Store<'c> + sequoia_cert_store::StoreUpdate<'c> + Send + Sync,
{
    fn update(&self, cert: Arc<sequoia_cert_store::LazyCert<'c>>) -> sequoia_openpgp::Result<()> {
        self.0.update(cert)
    }

    fn update_by(
        &self,
        cert: Arc<sequoia_cert_store::LazyCert<'c>>,
        merge_strategy: &dyn sequoia_cert_store::store::MergeCerts<'c>,
    ) -> sequoia_openpgp::Result<Arc<sequoia_cert_store::LazyCert<'c>>> {
        self.0.update_by(cert, merge_strategy)
    }
}

impl<'a, 'c> WriteStore<'a, 'c, Pep> {
    pub(crate) fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl<'a, 'c, T> StoreUpdate<'c> for ReadStore<'a, 'c, T>
where
    T: sequoia_cert_store::Store<'c> + StoreUpdate<'c>,
{
    fn update(&self, cert: Arc<sequoia_cert_store::LazyCert<'c>>) -> sequoia_openpgp::Result<()> {
        self.0.update(cert)
    }

    fn update_by(
        &self,
        cert: Arc<sequoia_cert_store::LazyCert<'c>>,
        merge_strategy: &dyn sequoia_cert_store::store::MergeCerts<'c>,
    ) -> sequoia_openpgp::Result<Arc<sequoia_cert_store::LazyCert<'c>>> {
        self.0.update_by(cert, merge_strategy)
    }
}

impl<'a, 'c> WriteStore<'a, 'c, Pep> {
    pub(crate) fn delete_fingerprint(&mut self, fingerprint: Fingerprint) -> anyhow::Result<()> {
        self.0.store_mut().cert_delete(fingerprint)
    }
}

impl<'a, 'c, T> sequoia_cert_store::Store<'c> for ReadStore<'a, 'c, T>
where
    T: sequoia_cert_store::Store<'c>,
{
    fn certs<'b>(&'b self) -> Box<dyn Iterator<Item = Arc<sequoia_cert_store::LazyCert<'c>>> + 'b>
    where
        'c: 'b,
    {
        self.0.store().certs()
    }

    fn fingerprints<'b>(&'b self) -> Box<dyn Iterator<Item = sequoia_openpgp::Fingerprint> + 'b> {
        self.0.store().fingerprints()
    }

    fn grep_email(
        &self,
        pattern: &str,
    ) -> sequoia_openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'c>>>> {
        self.0.store().grep_email(pattern)
    }

    fn grep_userid(
        &self,
        pattern: &str,
    ) -> sequoia_openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'c>>>> {
        self.0.store().grep_userid(pattern)
    }

    fn lookup_by_cert(
        &self,
        kh: &sequoia_openpgp::KeyHandle,
    ) -> sequoia_openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'c>>>> {
        self.0.store().lookup_by_cert(kh)
    }

    fn lookup_by_cert_fpr(
        &self,
        fingerprint: &sequoia_openpgp::Fingerprint,
    ) -> sequoia_openpgp::Result<Arc<sequoia_cert_store::LazyCert<'c>>> {
        self.0.store().lookup_by_cert_fpr(fingerprint)
    }

    fn lookup_by_cert_or_subkey(
        &self,
        kh: &sequoia_openpgp::KeyHandle,
    ) -> sequoia_openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'c>>>> {
        self.0.store().lookup_by_cert_or_subkey(kh)
    }

    fn lookup_by_email(
        &self,
        email: &str,
    ) -> sequoia_openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'c>>>> {
        self.0.store().lookup_by_email(email)
    }

    fn lookup_by_email_domain(
        &self,
        domain: &str,
    ) -> sequoia_openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'c>>>> {
        self.0.store().lookup_by_email_domain(domain)
    }

    fn lookup_by_userid(
        &self,
        userid: &sequoia_openpgp::packet::UserID,
    ) -> sequoia_openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'c>>>> {
        self.0.store().lookup_by_userid(userid)
    }

    fn prefetch_all(&self) {
        self.0.store().prefetch_all();
    }

    fn prefetch_some(&self, certs: &[sequoia_openpgp::KeyHandle]) {
        self.0.store().prefetch_some(certs);
    }

    fn select_userid(
        &self,
        query: &sequoia_cert_store::store::UserIDQueryParams,
        pattern: &str,
    ) -> sequoia_openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'c>>>> {
        self.0.store().select_userid(query, pattern)
    }
}

impl<'a, 'c, T> sequoia_cert_store::Store<'c> for WriteStore<'a, 'c, T>
where
    T: sequoia_cert_store::Store<'c>,
{
    fn certs<'b>(&'b self) -> Box<dyn Iterator<Item = Arc<sequoia_cert_store::LazyCert<'c>>> + 'b>
    where
        'c: 'b,
    {
        self.0.store().certs()
    }

    fn fingerprints<'b>(&'b self) -> Box<dyn Iterator<Item = sequoia_openpgp::Fingerprint> + 'b> {
        self.0.store().fingerprints()
    }

    fn grep_email(
        &self,
        pattern: &str,
    ) -> sequoia_openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'c>>>> {
        self.0.store().grep_email(pattern)
    }

    fn grep_userid(
        &self,
        pattern: &str,
    ) -> sequoia_openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'c>>>> {
        self.0.store().grep_userid(pattern)
    }

    fn lookup_by_cert(
        &self,
        kh: &sequoia_openpgp::KeyHandle,
    ) -> sequoia_openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'c>>>> {
        self.0.store().lookup_by_cert(kh)
    }

    fn lookup_by_cert_fpr(
        &self,
        fingerprint: &sequoia_openpgp::Fingerprint,
    ) -> sequoia_openpgp::Result<Arc<sequoia_cert_store::LazyCert<'c>>> {
        self.0.store().lookup_by_cert_fpr(fingerprint)
    }

    fn lookup_by_cert_or_subkey(
        &self,
        kh: &sequoia_openpgp::KeyHandle,
    ) -> sequoia_openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'c>>>> {
        self.0.store().lookup_by_cert_or_subkey(kh)
    }

    fn lookup_by_email(
        &self,
        email: &str,
    ) -> sequoia_openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'c>>>> {
        self.0.store().lookup_by_email(email)
    }

    fn lookup_by_email_domain(
        &self,
        domain: &str,
    ) -> sequoia_openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'c>>>> {
        self.0.store().lookup_by_email_domain(domain)
    }

    fn lookup_by_userid(
        &self,
        userid: &sequoia_openpgp::packet::UserID,
    ) -> sequoia_openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'c>>>> {
        self.0.store().lookup_by_userid(userid)
    }

    fn prefetch_all(&self) {
        self.0.store().prefetch_all();
    }

    fn prefetch_some(&self, certs: &[sequoia_openpgp::KeyHandle]) {
        self.0.store().prefetch_some(certs);
    }

    fn select_userid(
        &self,
        query: &sequoia_cert_store::store::UserIDQueryParams,
        pattern: &str,
    ) -> sequoia_openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'c>>>> {
        self.0.store().select_userid(query, pattern)
    }
}
