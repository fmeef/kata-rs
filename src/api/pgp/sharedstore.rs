use std::sync::Arc;

use sequoia_cert_store::Store;

pub struct SharedStore<'a, T>(Arc<sequoia_wot::store::CertStore<'a, 'a, T>>)
where
    T: Send + Sync + Store<'a> + sequoia_wot::sequoia_cert_store::Store<'a>;

impl<'a, T> SharedStore<'a, T>
where
    T: Send + Sync + Store<'a> + sequoia_wot::sequoia_cert_store::Store<'a>,
{
    pub(crate) fn new(store: sequoia_wot::store::CertStore<'a, 'a, T>) -> Self {
        Self(Arc::new(store))
    }

    pub(crate) fn store(&self) -> &'_ sequoia_wot::store::CertStore<'a, 'a, T> {
        self.0.as_ref()
    }
}

impl<'b, T> sequoia_wot::store::Store for SharedStore<'b, T>
where
    T: Send + Sync + Store<'b> + sequoia_wot::sequoia_cert_store::Store<'b>,
{
    fn reference_time(&self) -> std::time::SystemTime {
        self.0.reference_time()
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

    fn certifications_of(
        &self,
        target: &sequoia_openpgp::Fingerprint,
        min_depth: sequoia_wot::Depth,
    ) -> sequoia_openpgp::Result<Arc<Vec<sequoia_wot::CertificationSet>>> {
        self.0.certifications_of(target, min_depth)
    }
}

impl<'a, T> Clone for SharedStore<'a, T>
where
    T: Send + Sync + Store<'a> + sequoia_wot::sequoia_cert_store::Store<'a>,
{
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<'a, T> Store<'a> for SharedStore<'a, T>
where
    T: Send + Sync + Store<'a> + sequoia_wot::sequoia_cert_store::Store<'a>,
{
    fn lookup_by_cert(
        &self,
        kh: &sequoia_openpgp::KeyHandle,
    ) -> sequoia_openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'a>>>> {
        self.0.lookup_by_cert(kh)
    }

    fn lookup_by_cert_or_subkey(
        &self,
        kh: &sequoia_openpgp::KeyHandle,
    ) -> sequoia_openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'a>>>> {
        self.0.lookup_by_cert_or_subkey(kh)
    }

    fn select_userid(
        &self,
        query: &sequoia_cert_store::store::UserIDQueryParams,
        pattern: &str,
    ) -> sequoia_openpgp::Result<Vec<Arc<sequoia_cert_store::LazyCert<'a>>>> {
        self.0.select_userid(query, pattern)
    }

    fn fingerprints<'b>(&'b self) -> Box<dyn Iterator<Item = sequoia_openpgp::Fingerprint> + 'b> {
        self.0.fingerprints()
    }
}
