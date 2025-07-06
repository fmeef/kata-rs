pub mod db;

use lazy_static::lazy_static;

lazy_static! {
    static ref LOGGER: () = init_logging();
}

pub fn init_logging() {
    env_logger::init();
}
