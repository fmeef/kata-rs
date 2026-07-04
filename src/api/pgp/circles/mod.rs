use flutter_rust_bridge::frb;
use image_hasher::HashBytes;
use serde::de::Error;
use serde::{de::Visitor, ser::SerializeMap, Deserialize, Serialize};
use std::{collections::BTreeMap, hash::Hash, sync::RwLockReadGuard};

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
    frb_generated::{RustAutoOpaque, StreamSink},
};

pub mod app;
pub mod circle;

#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord)]
#[frb(non_opaque)]
enum CircleOrRef<'a> {
    Circle(&'a Circle),
    User(&'a UserHandle),
    App(&'a CircleApp),
}

#[derive(Debug, Clone)]
#[frb(non_opaque)]
pub enum CircleOr {
    Circle(RustAutoOpaque<Circle>),
    User(RustAutoOpaque<UserHandle>),
    App(RustAutoOpaque<CircleApp>),
}

impl Serialize for CircleOr {
    fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            Self::Circle(circle) => {
                map.serialize_key("circle")?;
                map.serialize_value(&*circle.blocking_read())?;
            }

            Self::User(user) => {
                map.serialize_key("user")?;
                map.serialize_value(&*user.blocking_read())?;
            }

            Self::App(app) => {
                map.serialize_key("app")?;
                map.serialize_value(&*app.blocking_read())?;
            }
        }

        map.end()
    }
}

struct CircleOrVisitor;

impl<'de> Visitor<'de> for CircleOrVisitor {
    type Value = CircleOr;
    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("expecting a CircleOr")
    }

    fn visit_map<A>(self, mut map: A) -> std::prelude::v1::Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "circle" => {
                    let v = map.next_value::<Circle>()?;
                    return Ok(CircleOr::Circle(RustAutoOpaque::new(v)));
                }
                "app" => {
                    let v = map.next_value::<CircleApp>()?;
                    return Ok(CircleOr::App(RustAutoOpaque::new(v)));
                }
                "user" => {
                    let v = map.next_value::<UserHandle>()?;
                    return Ok(CircleOr::User(RustAutoOpaque::new(v)));
                }
                _ => (),
            }
        }

        Err(A::Error::custom("no map key/value"))
    }
}

impl<'de> Deserialize<'de> for CircleOr {
    fn deserialize<D>(deserializer: D) -> std::prelude::v1::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(CircleOrVisitor)
    }
}

impl PartialEq for CircleOr {
    fn eq(&self, other: &Self) -> bool {
        let me = match self {
            CircleOr::App(app) => CircleOrRef::App(&app.blocking_read()),
            CircleOr::User(user) => CircleOrRef::User(&user.blocking_read()),
            CircleOr::Circle(circle) => CircleOrRef::Circle(&circle.blocking_read()),
        };

        let alt = match other {
            CircleOr::App(app) => CircleOrRef::App(&app.blocking_read()),
            CircleOr::User(user) => CircleOrRef::User(&user.blocking_read()),
            CircleOr::Circle(circle) => CircleOrRef::Circle(&circle.blocking_read()),
        };

        alt.eq(&me)
    }
}

impl PartialOrd for CircleOr {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let me = match self {
            CircleOr::App(app) => CircleOrRef::App(&app.blocking_read()),
            CircleOr::User(user) => CircleOrRef::User(&user.blocking_read()),
            CircleOr::Circle(circle) => CircleOrRef::Circle(&circle.blocking_read()),
        };

        let alt = match other {
            CircleOr::App(app) => CircleOrRef::App(&app.blocking_read()),
            CircleOr::User(user) => CircleOrRef::User(&user.blocking_read()),
            CircleOr::Circle(circle) => CircleOrRef::Circle(&circle.blocking_read()),
        };

        me.partial_cmp(&alt)
    }
}

impl Eq for CircleOr {}

impl Ord for CircleOr {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let me = match self {
            CircleOr::App(app) => CircleOrRef::App(&app.blocking_read()),
            CircleOr::User(user) => CircleOrRef::User(&user.blocking_read()),
            CircleOr::Circle(circle) => CircleOrRef::Circle(&circle.blocking_read()),
        };

        let alt = match other {
            CircleOr::App(app) => CircleOrRef::App(&app.blocking_read()),
            CircleOr::User(user) => CircleOrRef::User(&user.blocking_read()),
            CircleOr::Circle(circle) => CircleOrRef::Circle(&circle.blocking_read()),
        };
        me.cmp(&alt)
    }
}

impl CircleLike for CircleOr {
    #[frb(sync)]
    fn get_id(&self) -> Vec<u8> {
        match self {
            Self::App(a) => a.blocking_read().get_id(),
            Self::User(u) => u.blocking_read().get_id(),
            Self::Circle(c) => c.blocking_read().get_id(),
        }
    }
    #[frb(sync)]
    fn get_id_userhandle(&self) -> UserHandle {
        match self {
            Self::App(a) => a.blocking_read().get_id_userhandle(),
            Self::User(u) => u.blocking_read().get_id_userhandle(),
            Self::Circle(c) => c.blocking_read().get_id_userhandle(),
        }
    }
    #[frb(sync)]
    fn get_member(&self, id: UserHandle) -> Option<CircleEntry> {
        match self {
            Self::App(a) => a.blocking_read().get_member(id),
            Self::User(u) => u.blocking_read().get_member(id),
            Self::Circle(c) => c.blocking_read().get_member(id),
        }
    }
    #[frb(sync)]
    fn get_type(&self) -> CircleType {
        match self {
            Self::App(a) => a.blocking_read().get_type(),
            Self::User(u) => u.blocking_read().get_type(),
            Self::Circle(c) => c.blocking_read().get_type(),
        }
    }

    fn insert(&self, db: &SqliteDb) -> anyhow::Result<()> {
        self.to_db(db)
    }

    fn iter_members(&self, sink: StreamSink<CircleEntry>) {
        match self {
            Self::App(a) => a.blocking_read().iter_members(sink),
            Self::User(u) => u.blocking_read().iter_members(sink),
            Self::Circle(c) => c.blocking_read().iter_members(sink),
        }
    }

    fn verify(&self) -> anyhow::Result<bool> {
        match self {
            Self::App(a) => a.blocking_read().verify(),
            Self::User(u) => u.blocking_read().verify(),
            Self::Circle(c) => c.blocking_read().verify(),
        }
    }
}

impl Hash for CircleOr {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(&self.get_id());
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TagOr {
    content: MaybeDeleted,
    tag: Option<MemberTag>,
}

fn get_children(
    children: &BTreeMap<Vec<u8>, Vec<u8>>,
    members: &BTreeMap<Vec<u8>, CircleWithMembers>,
) -> Result<BTreeMap<Vec<u8>, TagOr>> {
    let mut out = BTreeMap::new();
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
                let handle = CircleOr::User(RustAutoOpaque::new(handle));
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
                circle.inner.members = get_children_parent(
                    children,
                    members,
                    children.get(parent).map(|v| v.as_slice()),
                )?
                .into_iter()
                .flat_map(|(v, u)| u.content.into_option().map(|u| (v, u)))
                .collect();
                circle.update_digest();
                let circle = CircleOr::Circle(RustAutoOpaque::new(circle));
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
                let id = app.get_id().to_owned();
                let app = if item.deleted.unwrap_or_default() {
                    MaybeDeleted::Deleted(item.get_id_userhandle()?)
                } else {
                    MaybeDeleted::Member(CircleOr::App(RustAutoOpaque::new(app)))
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
    pub(crate) fn empty() -> Self {
        Self::User(RustAutoOpaque::new(UserHandle::RawBytes(vec![])))
    }

    pub fn id_hex(&self) -> String {
        match self {
            Self::App(a) => a.blocking_read().inner.owner.name(),
            Self::Circle(s) => s.blocking_read().inner.id.name(),
            Self::User(u) => u.blocking_read().name(),
        }
    }

    pub fn to_db(&self, db: &SqliteDb) -> anyhow::Result<()> {
        match self {
            CircleOr::App(app) => app.blocking_read().to_db(db),
            CircleOr::Circle(circle) => circle.blocking_read().to_db(db),
            CircleOr::User(user) => user.blocking_read().to_db(db),
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

        Ok(res
            .into_values()
            .flat_map(|v| v.content.into_option())
            .collect())
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
}

impl std::io::Read for &CircleOr {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match *self {
            CircleOr::Circle(v) => {
                let n = v.blocking_read();
                let n = n.inner.id.as_bytes();
                buf[0..n.len()].copy_from_slice(n);
                Ok(0)
            }
            CircleOr::User(v) => {
                let n = v.blocking_read();
                let n = n.as_bytes();
                buf[0..n.len()].copy_from_slice(n);
                Ok(0)
            }
            CircleOr::App(v) => {
                let n = v.blocking_read();
                let n = n.inner.owner.as_bytes();
                buf[0..n.len()].copy_from_slice(n);
                Ok(0)
            }
        }
    }
}

impl CircleOr {
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
            CircleOr::Circle(circle) => circle.blocking_read().inner.id.clone(),
            CircleOr::App(app) => app.blocking_read().inner.owner.clone(),
            CircleOr::User(user) => user.blocking_read().clone(),
        }
    }

    pub(crate) fn as_read<'a>(&'a self) -> impl std::io::Read + 'a {
        self
    }

    pub(crate) fn as_bytes(&self) -> Vec<u8> {
        match self {
            Self::Circle(v) => v.blocking_read().inner.id.as_bytes().to_owned(),
            Self::User(v) => v.blocking_read().as_bytes().to_owned(),
            Self::App(v) => v.blocking_read().inner.owner.as_bytes().to_owned(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        api::{
            db::store::CertDao,
            pgp::{
                circles::{app::MemberTag, CircleOr},
                test_config, UserHandle,
            },
            PgpApp, PgpAppTrait,
        },
        frb_generated::RustAutoOpaque,
    };

    #[test]
    fn user_store_read() {
        let app = PgpApp::create(test_config("app")).unwrap();

        let v = UserHandle::from_hex("9FCF6558AC4927F1E7A43D80317375B449854036").unwrap();
        let id = v.name();
        let user = CircleOr::User(RustAutoOpaque::new(v));
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
        let user = CircleOr::User(RustAutoOpaque::new(v));
        let circle = app.create_circle(vec![user]).unwrap();
        let id = circle.inner.id.name();
        let circle = CircleOr::Circle(RustAutoOpaque::new(circle));
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
        let mut circle = app.create_app(&key.cert.fingerprint).unwrap();
        let id = circle.inner.owner.name();
        circle.add_user(v.clone(), MemberTag::Merge).unwrap();
        let circle = CircleOr::App(RustAutoOpaque::new(circle));

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
