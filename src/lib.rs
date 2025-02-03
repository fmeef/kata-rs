#![feature(allocator_api)]
#![allow(unexpected_cfgs)]
pub use crate::scatterbrain::api::types::GetType;
use flutter_rust_bridge::frb;
pub mod api;
pub(crate) mod db_helpers;
pub(crate) mod error;
mod frb_generated;
pub use scatterbrain;
#[frb(ignore)]
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/subrosaproto.rs"));
}
