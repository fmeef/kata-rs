use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};

use flutter_rust_bridge::frb;
use serde::{Deserialize, Serialize};

use crate::{
    api::{
        db::{
            store::{CircleWithMembers, DbMembers},
            utils::HexConvert,
        },
        pgp::{
            circles::{
                app::{AppMember, CircleApp, MemberTag},
                circle::{Circle, CircleInner},
            },
            UserHandle,
        },
        SqliteDb,
    },
    error::{InternalErr, Result},
    frb_generated::StreamSink,
};

pub mod app;
pub mod circle;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord)]
#[frb(non_opaque)]
#[serde(rename_all = "snake_case")]
pub enum CircleOr {
    Circle(Circle),
    User(UserHandle),
    App(CircleApp),
}

impl CircleOr {
    pub(crate) fn get_db_type(&self) -> &str {
        match self {
            Self::Circle(_) => "circle",
            Self::User(_) => "user",
            Self::App(_) => "app",
        }
    }

    pub fn id_hex(&self) -> String {
        match self {
            Self::App(a) => a.inner.owner.name(),
            Self::Circle(s) => s.inner.id.name(),
            Self::User(u) => u.name(),
        }
    }

    pub fn to_db(&self, db: &SqliteDb) -> anyhow::Result<()> {
        match self {
            CircleOr::App(app) => app.to_db(db),
            CircleOr::Circle(circle) => circle.to_db(db),
            CircleOr::User(user) => user.to_db(db),
        }
    }

    pub fn from_db(members: Vec<CircleWithMembers>) -> Result<Vec<CircleOr>> {
        let mut result = BTreeMap::new();
        let mut member_map = BTreeMap::new();
        for member in members.iter() {
            let tag = member.get_tag()?;
            if let Some(ref memberid) = member.get_member_id()? {
                println!("test member {member:?}");
                match member_map.entry(member.get_id()?) {
                    Entry::Vacant(v) => {
                        let mut m = BTreeSet::new();
                        m.insert((memberid.to_owned(), tag));
                        v.insert(m);
                    }
                    Entry::Occupied(mut occupied) => {
                        occupied.get_mut().insert((memberid.to_owned(), tag));
                    }
                }
            }
        }
        for member in members {
            match result.entry(member.get_id()?) {
                Entry::Vacant(v) => {
                    match member.circle_type.as_ref() {
                        "user" => {
                            let handle = member.get_id_userhandle()?;
                            let handle = CircleOr::User(handle);
                            v.insert(handle);
                        }
                        "circle" => {
                            let circle = Circle::new_mut(member.get_author()?, member.sig)?;
                            // circle.inner.members.insert()
                            let circle = CircleOr::Circle(circle);
                            v.insert(circle);
                        }
                        "app" => {
                            let app = CircleApp::new_empty(member.get_author()?, member.sig)?;

                            let app = CircleOr::App(app);

                            v.insert(app);
                        }
                        _ => return Err(InternalErr::InvalidCircleType(member.circle_type)),
                    }
                }
                Entry::Occupied(v) => {
                    // match member.circle_type.as_ref() {
                    //     "circle" => todo!(),
                    //     "user" => return Err(InternalErr::InvalidCircleType(member.circle_type)),
                    //     "app" => todo!(),
                    //     _ => return Err(InternalErr::InvalidCircleType(member.circle_type)),
                    // };
                }
            }
        }

        let res = result
            .keys()
            .cloned()
            .map(|k| {
                let children = member_map.remove(&k).unwrap_or_default();
                match result.get(&k).cloned().unwrap() {
                    CircleOr::App(mut app) => {
                        app.inner.children = children
                            .into_iter()
                            .filter_map(|(v, tag)| tag.map(|tag| (v, tag)))
                            .map(|(v, tag)| {
                                (
                                    v.clone(),
                                    AppMember {
                                        member: result.get(&v).cloned(),
                                        tag,
                                    },
                                )
                            })
                            .collect();
                        CircleOr::App(app)
                    }
                    CircleOr::Circle(mut circle) => {
                        circle.inner.members = children
                            .into_iter()
                            .filter(|(_, tag)| tag.is_none())
                            .filter_map(|(v, _)| result.get(&v).cloned().map(|r| (v, r)))
                            .collect();

                        circle.update_digest();
                        CircleOr::Circle(circle)
                    }
                    v => v,
                }
            })
            .collect();

        Ok(res)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CircleEntry {
    pub id: UserHandle,
    pub content: Option<CircleOr>,
    pub tag: Option<MemberTag>,
}

impl CircleEntry {
    pub(crate) fn from_app_member(member: AppMember, id: UserHandle) -> Self {
        Self {
            id,
            content: member.member,
            tag: Some(member.tag),
        }
    }

    pub(crate) fn from_circle_or(circleor: CircleOr) -> Self {
        Self {
            id: UserHandle::RawBytes(circleor.get_id().to_owned()),
            content: Some(circleor),
            tag: None,
        }
    }
}

pub trait CircleLike {
    fn iter_members(&self, sink: StreamSink<CircleEntry>);
    fn consume_members(self) -> Vec<CircleEntry>;
    fn get_member(&self, id: UserHandle) -> Option<CircleEntry>;
    fn verify(&self) -> anyhow::Result<bool>;
}

impl CircleOr {
    pub(crate) fn get_id(&self) -> &'_ [u8] {
        match self {
            CircleOr::Circle(Circle {
                inner: CircleInner { id, .. },
                ..
            }) => id.as_bytes(),
            CircleOr::App(CircleApp { inner, .. }) => inner.owner.as_bytes(),
            CircleOr::User(user) => user.as_bytes(),
        }
    }
    pub(crate) fn as_bytes(&self) -> &'_ [u8] {
        match self {
            Self::Circle(Circle {
                inner: CircleInner { id, .. },
                ..
            }) => id.as_bytes(),
            Self::User(user) => user.as_bytes(),
            Self::App(app) => app.inner.owner.as_bytes(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::api::{
        db::store::CertDao,
        pgp::{circles::CircleOr, test_config, UserHandle},
        PgpApp,
    };

    #[test]
    fn user_store_read() {
        let app = PgpApp::create(test_config("app")).unwrap();

        let v = UserHandle::from_hex("9FCF6558AC4927F1E7A43D80317375B449854036").unwrap();
        let id = v.name();
        let user = CircleOr::User(v);
        user.to_db(&app.pgp.db).unwrap();
        let out = app.pgp.db.get_circle_by_id(&id).unwrap();
        assert!(!out.is_empty());
        let newcircle = CircleOr::from_db(out).unwrap();
        assert!(!newcircle.is_empty());
        // assert_eq!(circle, newcircle);
    }

    #[test]
    fn circle_store_read() {
        let app = PgpApp::create(test_config("app")).unwrap();

        let v = UserHandle::from_hex("9FCF6558AC4927F1E7A43D80317375B449854036").unwrap();
        let user = CircleOr::User(v);
        let circle = app.create_circle(vec![user]).unwrap();
        let id = circle.inner.id.name();
        let circle = CircleOr::Circle(circle);
        circle.to_db(&app.pgp.db).unwrap();

        let out = app.pgp.db.get_circles_join().unwrap();

        assert_eq!(out.len(), 2);

        let newcircle = CircleOr::from_db(out).unwrap();
        assert!(!newcircle.is_empty());
        assert_eq!(circle, newcircle[0]);
    }
}
