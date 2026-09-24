use crate::api::pgp::{
    circles::{app::CircleApp, circle::Circle},
    UserHandle,
};

#[derive(Debug, Clone)]
pub enum CircleOr {
    Circle(Circle),
    User(UserHandle),
    App(CircleApp),
}
