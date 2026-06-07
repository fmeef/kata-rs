use std::collections::BTreeMap;

use flutter_rust_bridge::frb;
use serde::{Deserialize, Serialize};

use crate::{
    api::{
        db::store::CircleWithMembers,
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
#[frb(opaque)]
#[serde(rename_all = "snake_case")]
pub enum CircleOr {
    Circle(Circle),
    User(UserHandle),
    App(CircleApp),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TagOr {
    content: Option<CircleOr>,
    tag: Option<MemberTag>,
}

fn get_children(
    children: &BTreeMap<Vec<u8>, Vec<u8>>,
    members: &BTreeMap<Vec<u8>, CircleWithMembers>,
) -> Result<BTreeMap<Vec<u8>, TagOr>> {
    let mut out = BTreeMap::new();
    println!("get_children start members={members:?}");
    for (k, _) in members
        .iter()
        .filter(|(_, p)| p.get_parent_id().map(|v| v.is_none()).unwrap_or_default())
    {
        let v = get_children_parent(children, members, Some(k.as_slice()))?;
        println!("get_children {v:?}");
        out.extend(v.into_iter());
    }
    Ok(out)
}
fn get_children_parent(
    children: &BTreeMap<Vec<u8>, Vec<u8>>,
    members: &BTreeMap<Vec<u8>, CircleWithMembers>,
    parent: Option<&[u8]>,
) -> Result<BTreeMap<Vec<u8>, TagOr>> {
    let mut out = BTreeMap::new();
    let parent = match parent {
        Some(v) => v,
        None => return Ok(out),
    };
    for (_, item) in members.iter().filter(|(k, _)| *k == parent) {
        println!("get_children_parent {item:?}");
        match item.circle_type.as_ref() {
            "user" => {
                let handle = item.get_id_userhandle()?;

                let handle = CircleOr::User(handle);
                out.insert(
                    handle.get_id().to_owned(),
                    TagOr {
                        content: Some(handle),
                        tag: item.get_tag()?,
                    },
                );
            }
            "circle" => {
                let mut circle = Circle::new_mut(item.get_author()?, item.sig.clone())?;
                circle.inner.members = get_children_parent(
                    children,
                    members,
                    children.get(parent).map(|v| v.as_slice()),
                )?
                .into_iter()
                .flat_map(|(v, u)| u.content.map(|u| (v, u)))
                .collect();
                circle.update_digest();
                let circle = CircleOr::Circle(circle);
                out.insert(
                    circle.get_id().to_owned(),
                    TagOr {
                        content: Some(circle),
                        tag: item.get_tag()?,
                    },
                );
            }
            "app" => {
                let mut app = CircleApp::new_empty(item.get_author()?, item.sig.clone())?;
                app.inner.children = get_children_parent(
                    children,
                    members,
                    children.get(parent).map(|v| v.as_slice()),
                )?
                .into_iter()
                .flat_map(|(v, u)| {
                    u.tag.map(|tag| {
                        (
                            v,
                            AppMember {
                                member: u.content,
                                tag,
                            },
                        )
                    })
                })
                .collect();
                let app = CircleOr::App(app);

                out.insert(
                    app.get_id().to_owned(),
                    TagOr {
                        content: Some(app),
                        tag: item.get_tag()?,
                    },
                );
            }
            _ => return Err(InternalErr::InvalidCircleType(item.circle_type.clone())),
        }
    }
    Ok(out)
}

impl CircleOr {
    pub fn id_hex(&self) -> String {
        match self {
            Self::App(a) => a.inner.owner.name(),
            Self::Circle(s) => s.inner.id.name(),
            Self::User(u) => u.name(),
        }
    }

    pub fn to_db(&mut self, db: &SqliteDb) -> anyhow::Result<()> {
        match self {
            CircleOr::App(app) => app.to_db(db),
            CircleOr::Circle(circle) => circle.to_db(db),
            CircleOr::User(user) => user.to_db(db),
        }
    }

    pub fn from_db(members: Vec<CircleWithMembers>) -> Result<Vec<CircleOr>> {
        let mut out = BTreeMap::new();

        let mut children = BTreeMap::new();
        for member in members {
            if let Some(parent) = member.get_parent_id()? {
                children.insert(parent, member.get_id()?);
                out.insert(member.get_id()?, member);
            } else {
                out.insert(member.get_id()?, member);
            }
        }

        let res = get_children(&children, &out)?;

        Ok(res.into_values().flat_map(|v| v.content).collect())
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
    fn get_id(&self) -> Vec<u8>;
    fn get_id_userhandle(&self) -> UserHandle;
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
        pgp::{
            circles::{app::MemberTag, CircleOr},
            test_config, UserHandle,
        },
        PgpApp, PgpAppTrait,
    };

    #[test]
    fn user_store_read() {
        let app = PgpApp::create(test_config("app")).unwrap();

        let v = UserHandle::from_hex("9FCF6558AC4927F1E7A43D80317375B449854036").unwrap();
        let id = v.name();
        let mut user = CircleOr::User(v);
        user.to_db(&app.pgp.db).unwrap();
        let out = app.pgp.db.get_circle_by_id(&id).unwrap();
        assert!(!out.is_empty());
        let newcircle = CircleOr::from_db(out).unwrap();
        assert!(!newcircle.is_empty());
        assert_eq!(user, newcircle[0]);
    }

    #[test]
    fn circle_store_read() {
        let app = PgpApp::create(test_config("app")).unwrap();

        let v = UserHandle::from_hex("9FCF6558AC4927F1E7A43D80317375B449854036").unwrap();
        let user = CircleOr::User(v);
        let circle = app.create_circle(vec![user]).unwrap();
        let id = circle.inner.id.name();
        let mut circle = CircleOr::Circle(circle);
        circle.to_db(&app.pgp.db).unwrap();

        let out = app.pgp.db.get_circles_join().unwrap();
        println!("{out:?}");
        let out = app.pgp.db.get_circle_by_id(&id).unwrap();

        assert_eq!(out.len(), 2);

        let newcircle = CircleOr::from_db(out).unwrap();
        assert!(!newcircle.is_empty());
        assert_eq!(newcircle.len(), 1);
        assert_eq!(circle, newcircle[0]);
    }

    #[test]
    fn app_store_read() {
        let app = PgpApp::create(test_config("app")).unwrap();
        let key = app
            .generate_key("test@example.com".to_owned())
            .generate()
            .unwrap();
        let v = UserHandle::from_hex("9FCF6558AC4927F1E7A43D80317375B449854036").unwrap();
        let mut circle = app.create_app(key.cert.fingerprint).unwrap();
        let id = circle.inner.owner.name();
        circle.add_user(v.clone(), MemberTag::Merge).unwrap();
        let user = CircleOr::User(v);

        let mut circle = CircleOr::App(circle);

        circle.to_db(&app.pgp.db).unwrap();

        let out = app.pgp.db.get_circles_join().unwrap();
        println!("{out:?}");
        let out = app.pgp.db.get_circle_by_id(&id).unwrap();

        assert_eq!(out.len(), 2);

        let newcircle = CircleOr::from_db(out).unwrap();
        assert!(!newcircle.is_empty());
        assert_eq!(newcircle.len(), 1);
        assert_eq!(circle, newcircle[0]);
    }
}
