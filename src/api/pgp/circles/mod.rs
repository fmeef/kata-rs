use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};

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

fn get_children(
    children: &BTreeMap<Vec<u8>, Vec<u8>>,
    members: &BTreeMap<Vec<u8>, CircleWithMembers>,
) -> Result<BTreeMap<Vec<u8>, CircleOr>> {
    let mut out = BTreeMap::new();
    println!("get_children start members={members:?}");
    for (k, m) in members
        .iter()
        .filter(|(k, p)| p.get_parent_id().map(|v| v.is_none()).unwrap_or_default())
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
) -> Result<BTreeMap<Vec<u8>, CircleOr>> {
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
                out.insert(handle.get_id().to_owned(), handle);
            }
            "circle" => {
                let mut circle = Circle::new_mut(item.get_author()?, item.sig.clone())?;
                circle.inner.members = get_children_parent(
                    children,
                    members,
                    children.get(parent).map(|v| v.as_slice()),
                )?;
                circle.update_digest();
                let circle = CircleOr::Circle(circle);
                out.insert(circle.get_id().to_owned(), circle);
            }
            "app" => {
                let app = CircleApp::new_empty(item.get_author()?, item.sig.clone())?;
                let app = CircleOr::App(app);
                out.insert(app.get_id().to_owned(), app);
            }
            _ => return Err(InternalErr::InvalidCircleType(item.circle_type.clone())),
        }
    }
    Ok(out)
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

        Ok(res.into_values().collect())
    }

    pub fn from_db_fake(members: Vec<CircleWithMembers>) -> Result<Vec<CircleOr>> {
        let mut result = BTreeMap::new();
        let mut member_map = BTreeMap::new();
        for member in members.iter() {
            for parentcheck in members.iter() {
                let tag = member.get_tag()?;
                if let Some(parent) = parentcheck.get_parent_id()? {
                    let memberid = member.get_id()?;
                    println!("member_insert {parent:?} {memberid:?}");
                    if parent == memberid {
                        match member_map.entry(memberid) {
                            Entry::Vacant(v) => {
                                let mut m = BTreeSet::new();
                                m.insert((parent, tag));
                                v.insert(m);
                            }
                            Entry::Occupied(mut occupied) => {
                                occupied.get_mut().insert((parent, tag));
                            }
                        }
                    }
                }
            }
        }
        for member in members {
            if member.get_parent_id()?.is_some() {
                continue;
            }
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

        println!("member_map={member_map:?}");

        let res = result
            .keys()
            .cloned()
            .map(|k| {
                //TODO remove
                let children = member_map.get(&k).cloned().unwrap_or_default();
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
                        println!("test member {children:?} k={k:?}");
                        circle.inner.members = children
                            .into_iter()
                            .filter(|(v, tag)| tag.is_none())
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
        pgp::{circles::CircleOr, test_config, UserHandle},
        PgpApp,
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
}
