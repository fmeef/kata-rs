pub mod db;
pub mod image;
pub mod pgp;

pub use std::path::PathBuf;

use flutter_rust_bridge::frb;
use lazy_static::lazy_static;

use crate::api::{db::connection::SqliteDb, pgp::PgpService};

lazy_static! {
    static ref LOGGER: () = init_logging();
}

pub fn init_logging() {
    env_logger::init();
}

#[frb(opaque)]
pub struct Config {
    keystore_path: Option<PathBuf>,
    db_path: Option<PathBuf>,
}

impl Config {
    #[frb(sync)]
    pub fn new() -> Self {
        Self {
            keystore_path: None,
            db_path: None,
        }
    }
}

pub struct PgpApp {
    pub db: SqliteDb,
    pub pgp: PgpService,
}
