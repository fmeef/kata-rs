use flutter_rust_bridge::frb;

use crate::api::pgp::{
    circles::{app::CircleApp, circle::Circle},
    UserHandle,
};

pub mod app;
pub mod circle;

#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord)]
#[frb(non_opaque)]
pub enum CircleOr {
    Circle(Circle),
    User(UserHandle),
    App(CircleApp),
}

impl CircleOr {
    pub(crate) fn get_id(&self) -> &'_ [u8] {
        match self {
            CircleOr::Circle(Circle { id, .. }) => id.as_bytes(),
            CircleOr::App(CircleApp { inner, .. }) => inner.owner.as_bytes(),
            CircleOr::User(user) => user.as_bytes(),
        }
    }
    pub(crate) fn as_bytes(&self) -> &'_ [u8] {
        match self {
            Self::Circle(Circle { id, .. }) => id.as_bytes(),
            Self::User(user) => user.as_bytes(),
            Self::App(app) => app.inner.owner.as_bytes(),
        }
    }
}
