use sequoia_openpgp::policy::StandardPolicy;
use sequoia_wot::store::CertStore;
use std::{path::PathBuf, str::FromStr, sync::Arc};
use tokio::sync::RwLock;

use crate::api::pgp::wot::CertNetworkBuilder;

pub mod keys;
pub mod keyserver;
pub mod sign;
pub mod wot;

pub static POLICY: StandardPolicy = StandardPolicy::new();

pub trait Verifier {
    fn verify(&self, data: Vec<u8>) -> bool;
}

#[derive(Clone)]
pub struct PgpService {
    store: Arc<CertStore<'static, 'static, sequoia_cert_store::CertStore<'static>>>,
    network: Arc<RwLock<CertNetworkBuilder>>,
    policy: StandardPolicy<'static>,
}

impl PgpService {
    pub fn new(store_dir: &str) -> anyhow::Result<Self> {
        let store = Arc::new(CertStore::from_store(
            sequoia_cert_store::CertStore::open(&PathBuf::from_str(store_dir)?)?,
            &POLICY,
            None,
        ));
        Ok(Self {
            store: store.clone(),
            policy: StandardPolicy::new(),
            network: Arc::new(RwLock::new(CertNetworkBuilder::new(store.as_ref())?)),
        })
    }
}
