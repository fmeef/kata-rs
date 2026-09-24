use std::{path::PathBuf, str::FromStr};

use flutter_rust_bridge::frb;
use sequoia_cert_store::{AccessMode, CertStore, Store, StoreUpdate};

use crate::api::{pgp::POLICY, SqliteDb};
#[frb(ignore)]
pub(crate) trait StoreProvider {
    type PgpStore<'a>: Send + Sync + Store<'a> + StoreUpdate<'a>
    where
        Self: 'a;
    fn store(&self) -> anyhow::Result<sequoia_wot::store::CertStore<'_, '_, Self::PgpStore<'_>>>;
}

#[derive(Clone)]
pub struct ProdStoreProvider {
    store_dir: String,
    sqlite_db: SqliteDb,
}

impl ProdStoreProvider {
    pub fn new(store_dir: String, sqlite_db: SqliteDb) -> Self {
        Self {
            store_dir,
            sqlite_db,
        }
    }
}

#[frb(ignore)]
impl StoreProvider for ProdStoreProvider {
    type PgpStore<'a> = CertStore<'a>;
    fn store<'a>(&'a self) -> anyhow::Result<sequoia_wot::store::CertStore<'_, 'a, CertStore<'a>>> {
        let mut store = sequoia_cert_store::CertStore::open(&PathBuf::from_str(&self.store_dir)?)?;
        store.add_backend(Box::new(self.sqlite_db.clone()), AccessMode::OnMiss);

        Ok(sequoia_wot::store::CertStore::from_store(
            store, &POLICY, None,
        ))
    }
}
