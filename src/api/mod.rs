pub mod db;

use lazy_static::lazy_static;
pub use scatterbrain;
pub mod net;
pub mod proto;

lazy_static! {
    static ref LOGGER: () = init_logging();
}

pub fn init_logging() {
    env_logger::init();
}
