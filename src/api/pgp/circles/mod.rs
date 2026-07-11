use std::{
    collections::{BTreeMap, BTreeSet},
    hash::Hash,
};

use flutter_rust_bridge::frb;
use serde::{Deserialize, Serialize};

use crate::{
    api::{
        db::store::CircleWithMembers,
        pgp::{
            circles::{
                app::{AppMember, CircleApp, MaybeDeleted, MemberTag},
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

impl CircleLike for CircleOr {
    #[frb(sync)]
    fn get_id(&self) -> Vec<u8> {
        match self {
            Self::App(a) => a.get_id(),
            Self::User(u) => u.get_id(),
            Self::Circle(c) => c.get_id(),
        }
    }
    #[frb(sync)]
    fn get_id_userhandle(&self) -> UserHandle {
        match self {
            Self::App(a) => a.get_id_userhandle(),
            Self::User(u) => u.get_id_userhandle(),
            Self::Circle(c) => c.get_id_userhandle(),
        }
    }
    #[frb(sync)]
    fn get_member(&self, id: UserHandle) -> Option<CircleEntry> {
        match self {
            Self::App(a) => a.get_member(id),
            Self::User(u) => u.get_member(id),
            Self::Circle(c) => c.get_member(id),
        }
    }
    #[frb(sync)]
    fn get_type(&self) -> CircleType {
        match self {
            Self::App(a) => a.get_type(),
            Self::User(u) => u.get_type(),
            Self::Circle(c) => c.get_type(),
        }
    }

    fn insert(&self, db: &SqliteDb) -> anyhow::Result<()> {
        self.to_db(db)
    }

    fn iter_members(&self, sink: StreamSink<CircleEntry>) {
        match self {
            Self::App(a) => a.iter_members(sink),
            Self::User(u) => u.iter_members(sink),
            Self::Circle(c) => c.iter_members(sink),
        }
    }

    fn verify(&self) -> anyhow::Result<bool> {
        match self {
            Self::App(a) => a.verify(),
            Self::User(u) => u.verify(),
            Self::Circle(c) => c.verify(),
        }
    }

    #[frb(sync)]
    fn get_members(&self) -> Vec<CircleEntry> {
        match self {
            Self::App(a) => a.get_members(),
            Self::Circle(c) => c.get_members(),
            Self::User(u) => u.get_members(),
        }
    }
}

impl Hash for CircleOr {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(self.get_id_ref());
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TagOr {
    content: MaybeDeleted,
    tag: Option<MemberTag>,
}

fn get_children(
    children: &BTreeMap<(String, Vec<u8>), BTreeSet<(String, Vec<u8>)>>,
    members: &BTreeMap<(String, Vec<u8>), CircleWithMembers>,
) -> Result<BTreeMap<Vec<u8>, TagOr>> {
    let mut out = BTreeMap::new();
    for ((t, k), m) in members
        .iter()
        .filter(|(_, p)| p.get_parent_id().map(|v| v.is_none()).unwrap_or_default())
    {
        let v = get_children_parent(children, members, Some((t, k.as_slice())))?;
        out.extend(v.into_iter());
    }
    Ok(out)
}
fn get_children_parent(
    children: &BTreeMap<(String, Vec<u8>), BTreeSet<(String, Vec<u8>)>>,
    members: &BTreeMap<(String, Vec<u8>), CircleWithMembers>,
    parent: Option<(&str, &[u8])>,
) -> Result<BTreeMap<Vec<u8>, TagOr>> {
    let mut out = BTreeMap::new();
    let (tparent, parent) = match parent {
        Some(v) => v,
        None => return Ok(out),
    };
    for (_, item) in members.iter().filter(|((t, k), _)| *k == parent) {
        let parent = (tparent.to_owned(), parent.to_owned());
        // println!("get_children_parent {item:?}");
        match item.circle_type.as_ref() {
            "user" => {
                let handle = item.get_id_userhandle()?;

                let handle = CircleOr::User(handle);
                out.insert(
                    handle.get_id().to_owned(),
                    TagOr {
                        content: MaybeDeleted::Member(handle),
                        tag: item.get_tag()?,
                    },
                );
            }
            "circle" => {
                let mut circle = Circle::new_mut(item.get_author()?, item.sig.clone())?;
                circle.inner.members = BTreeMap::new();
                if let Some(parent) = children.get(&parent) {
                    for (tparent, parent) in parent {
                        circle.inner.members.extend(
                            get_children_parent(
                                children,
                                members,
                                Some((tparent, parent.as_slice())),
                            )?
                            .into_iter()
                            .flat_map(|(v, u)| u.content.into_option().map(|u| (v, u))),
                        );
                    }
                }
                circle.update_digest();
                let circle = CircleOr::Circle(circle);
                out.insert(
                    circle.get_id().to_owned(),
                    TagOr {
                        content: MaybeDeleted::Member(circle),
                        tag: item.get_tag()?,
                    },
                );
            }
            "app" => {
                let mut app = CircleApp::new_empty(item.get_author()?, item.sig.clone())?;
                app.inner.children = BTreeMap::new();
                if let Some(parent) = children.get(&parent) {
                    for (tparent, parent) in parent {
                        app.inner.children.extend(
                            get_children_parent(
                                children,
                                members,
                                Some((tparent, parent.as_slice())),
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
                            }),
                        );
                    }
                }

                let id = app.get_id().to_owned();
                let app = if item.deleted.unwrap_or_default() {
                    println!("app with members {:?}", app.inner.children);
                    MaybeDeleted::Deleted(item.get_id_userhandle()?)
                } else {
                    MaybeDeleted::Member(CircleOr::App(app))
                };

                out.insert(
                    id,
                    TagOr {
                        content: app,
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

    pub fn to_db(&self, db: &SqliteDb) -> anyhow::Result<()> {
        match self {
            CircleOr::App(app) => app.to_db(db),
            CircleOr::Circle(circle) => circle.to_db(db),
            CircleOr::User(user) => user.to_db(db),
        }
    }

    pub fn from_db(members: Vec<CircleWithMembers>) -> Result<Vec<CircleOr>> {
        // println!("from_db {members:?}");
        let mut out = BTreeMap::new();

        let mut children = BTreeMap::new();

        for member in members {
            if let (Some(pty), Some(parent)) = (member.parent_type.clone(), member.get_parent_id()?)
            {
                let entry = children
                    .entry((pty, parent))
                    .or_insert_with(|| BTreeSet::new());
                entry.insert((member.circle_type.clone(), member.get_id()?));
                out.insert((member.circle_type.clone(), member.get_id()?), member);
            } else {
                out.insert((member.circle_type.clone(), member.get_id()?), member);
            }
        }

        let res = get_children(&children, &out)?;

        let res = res
            .into_values()
            .flat_map(|v| v.content.into_option())
            .filter(|p| match p {
                CircleOr::User(_) => false,
                _ => true,
            })
            .collect();

        // println!("get! {res:#?}");
        Ok(res)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CircleEntry {
    pub id: UserHandle,
    pub content: Option<CircleOr>,
    pub tag: Option<MemberTag>,
}

impl CircleEntry {
    pub(crate) fn from_app_member(member: AppMember, id: UserHandle) -> Self {
        Self {
            id,
            content: member.member.into_option(),
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
    #[frb(sync)]
    fn get_member(&self, id: UserHandle) -> Option<CircleEntry>;
    #[frb(sync)]
    fn get_members(&self) -> Vec<CircleEntry>;
    fn verify(&self) -> anyhow::Result<bool>;
    #[frb(sync)]
    fn get_id(&self) -> Vec<u8>;
    #[frb(sync)]
    fn get_id_userhandle(&self) -> UserHandle;
    #[frb(sync)]
    fn get_type(&self) -> CircleType;
    fn insert(&self, db: &SqliteDb) -> anyhow::Result<()>;
}

#[derive(Debug, Serialize, Deserialize)]
#[frb(non_opaque)]
pub enum CircleType {
    User,
    Circle,
    App,
}

#[frb(opaque)]
pub struct GenericCircle<'a>(Box<dyn CircleLike + Send + Sync + 'a>);

impl<'a> GenericCircle<'a> {
    pub fn new<T>(inner: T) -> GenericCircle<'a>
    where
        T: CircleLike + Send + Sync + 'a,
    {
        Self(Box::new(inner))
    }
}

impl<'a, T> CircleLike for &'a T
where
    T: CircleLike,
{
    #[frb(sync)]
    fn get_id(&self) -> Vec<u8> {
        (*self).get_id()
    }

    #[frb(sync)]
    fn get_id_userhandle(&self) -> UserHandle {
        (*self).get_id_userhandle()
    }

    #[frb(sync)]
    fn get_member(&self, id: UserHandle) -> Option<CircleEntry> {
        (*self).get_member(id)
    }

    fn iter_members(&self, sink: StreamSink<CircleEntry>) {
        (*self).iter_members(sink);
    }

    fn verify(&self) -> anyhow::Result<bool> {
        (*self).verify()
    }

    #[frb(sync)]
    fn get_type(&self) -> CircleType {
        (*self).get_type()
    }

    fn insert(&self, db: &SqliteDb) -> anyhow::Result<()> {
        (*self).insert(db)
    }

    #[frb(sync)]
    fn get_members(&self) -> Vec<CircleEntry> {
        (*self).get_members()
    }
}

impl<'a> CircleLike for GenericCircle<'a> {
    #[frb(sync)]
    fn get_id(&self) -> Vec<u8> {
        self.0.get_id()
    }

    #[frb(sync)]
    fn get_id_userhandle(&self) -> UserHandle {
        self.0.get_id_userhandle()
    }

    #[frb(sync)]
    fn get_member(&self, id: UserHandle) -> Option<CircleEntry> {
        self.0.get_member(id)
    }

    fn iter_members(&self, sink: StreamSink<CircleEntry>) {
        self.0.iter_members(sink);
    }

    fn verify(&self) -> anyhow::Result<bool> {
        self.0.verify()
    }

    #[frb(sync)]
    fn get_type(&self) -> CircleType {
        self.0.get_type()
    }

    fn insert(&self, db: &SqliteDb) -> anyhow::Result<()> {
        self.0.insert(db)
    }

    #[frb(sync)]
    fn get_members(&self) -> Vec<CircleEntry> {
        self.0.get_members()
    }
}

impl CircleOr {
    pub(crate) fn get_id_ref(&self) -> &'_ [u8] {
        match self {
            CircleOr::Circle(Circle {
                inner: CircleInner { id, .. },
                ..
            }) => id.as_bytes(),
            CircleOr::App(CircleApp { inner, .. }) => inner.owner.as_bytes(),
            CircleOr::User(user) => user.as_bytes(),
        }
    }

    // #[frb(sync)]
    // pub fn generic<'a>(&'a self) -> GenericCircle<'a> {
    //     match self {
    //         Self::App(ref app) => GenericCircle::new(app),
    //         Self::Circle(ref circle) => GenericCircle::new(circle),
    //         Self::User(ref user) => GenericCircle::new(user),
    //     }
    // }

    // pub(crate) fn into_userhandle(self) -> UserHandle {
    //     match self {
    //         CircleOr::Circle(Circle {
    //             inner: CircleInner { id, .. },
    //             ..
    //         }) => id,
    //         CircleOr::App(CircleApp { inner, .. }) => inner.owner,
    //         CircleOr::User(user) => user,
    //     }
    // }

    pub(crate) fn get_userhandle(&self) -> UserHandle {
        match self {
            CircleOr::Circle(Circle {
                inner: CircleInner { id, .. },
                ..
            }) => id.clone(),
            CircleOr::App(CircleApp { inner, .. }) => inner.owner.clone(),
            CircleOr::User(user) => user.clone(),
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
            circles::{app::MemberTag, CircleLike, CircleOr},
            test_config, UserHandle,
        },
        PgpApp, PgpAppTrait,
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
        assert!(newcircle.is_empty());
        //assert_eq!(user, newcircle[0]);
    }

    #[test]
    fn circle_store_read() {
        let app = PgpApp::create(test_config("app")).unwrap();

        let v = UserHandle::from_hex("9FCF6558AC4927F1E7A43D80317375B449854036").unwrap();
        let user = CircleOr::User(v);
        let circle = app.create_circle(vec![user]).unwrap();
        let circle = CircleOr::Circle(circle);
        circle.to_db(&app.pgp.db).unwrap();

        let out = app.pgp.db.get_circles_join().unwrap();
        println!("{out:?}");
        //   let out = app.pgp.db.get_circle_by_id(&id).unwrap();

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
        let u = UserHandle::from_hex("9FCF6558AC4927F1E7A43D80317375B449854037").unwrap();

        let mut circle = app.create_app(&key.cert.fingerprint).unwrap();
        let id = circle.inner.owner.name();
        circle.add_user(v.clone(), MemberTag::Merge).unwrap();
        circle.add_user(u.clone(), MemberTag::Merge).unwrap();

        let circle = CircleOr::App(circle);

        circle.to_db(&app.pgp.db).unwrap();

        let out = app.pgp.db.get_circles_join().unwrap();
        println!("{out:?}");
        // let out = app.pgp.db.get_circle_by_id(&id).unwrap();

        assert_eq!(out.len(), 3);

        let newcircle = CircleOr::from_db(out).unwrap();
        assert!(!newcircle.is_empty());
        assert_eq!(newcircle.len(), 1);
        assert_eq!(circle.get_members(), newcircle[0].get_members());
    }
}
