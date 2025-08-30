use std::sync::Arc;

use sequoia_cert_store::{store::Certs, LazyCert, Store};
use sequoia_openpgp::policy::StandardPolicy;
pub use sequoia_wot::{store::CertStore, Network, Roots};

pub struct CertNetworkBuilder {
    certs: Vec<Arc<LazyCert<'static>>>,
    policy: StandardPolicy<'static>,
}

pub struct CertNetwork<'a>(Network<CertStore<'a, 'a, Certs<'a>>>);

impl<'a> CertNetwork<'a> {}

impl CertNetworkBuilder {
    pub(crate) fn new(
        store: &CertStore<'static, 'static, sequoia_cert_store::CertStore<'static>>,
    ) -> anyhow::Result<Self> {
        let s = Self {
            certs: store.certs().collect(),
            policy: StandardPolicy::new(),
        };
        Ok(s)
    }

    pub fn get_all_certs<R: Into<Roots>>(&self, roots: R) -> anyhow::Result<CertNetwork<'_>> {
        let certs = self.certs.iter().map(|v| v.to_cert().unwrap());
        let network = Network::from_cert_refs(certs, &self.policy, None, roots)?;

        Ok(CertNetwork(network))
    }
}
