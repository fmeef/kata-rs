#![allow(unexpected_cfgs)]
#![allow(mismatched_lifetime_syntaxes)]

use lazy_static::lazy_static;
pub mod api;
#[cfg(not(feature = "flutter"))]
pub(crate) mod circles;
pub(crate) mod db_helpers;
pub(crate) mod error;
#[cfg(feature = "flutter")]
pub(crate) mod frb_generated;
pub(crate) mod pgp;

lazy_static! {
    pub(crate) static ref LOG_SETUP: () = env_logger::init();
}
