use anyhow::anyhow;
use flutter_rust_bridge::frb;
use sequoia_openpgp::{Fingerprint, KeyHandle};

use crate::api::db::store::CertDao;
use crate::api::db::utils::HexConvert;
use crate::api::pgp::PgpServiceTrait;
use crate::api::{PgpApp, PgpAppTrait};
use crate::{
    api::{
        db::store::CircleWithMembers,
        pgp::{
            circles::{
                app::{AppMember, CircleApp, MaybeDeleted, MemberTag},
                circle::Circle,
            },
            UserHandle,
        },
        SqliteDb,
    },
    error::{InternalErr, Result},
    frb_generated::{RustAutoOpaque, StreamSink},
};

use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, hash::Hash};

pub mod app;
pub mod circle;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[frb(non_opaque)]
pub struct CircleHandle {
    pub id: String,
    pub circle_type: CircleType,
}
// #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
// pub(crate) struct BinCircleHandle {
//     pub(crate) id: Vec<u8>,
//     pub(crate) circle_type: CircleType,
// }

// impl BinCircleHandle {
//     pub(crate) fn non_bin(&self) -> Result<CircleHandle> {
//         let res = CircleHandle {
//             id: match self.circle_type {
//                 CircleType::App => UserHandle::KeyHandle(
//                     KeyHandle::Fingerprint(Fingerprint::try_from(self.id.as_slice())?),
//                     None,
//                 )
//                 .name(),
//             },
//             circle_type: (),
//         };

//         Ok(res)
//     }
// }

impl CircleHandle {
    pub(crate) fn get_bin(&self) -> Result<Vec<u8>> {
        let mut res = Vec::<u8>::from_hex(&self.id)?;

        res.push(self.circle_type.get_type_u8());

        Ok(res)
    }

    fn get_bytes(&self) -> Result<Vec<u8>> {
        match self.circle_type {
            CircleType::Circle => Ok(Vec::<u8>::from_hex(&self.id)?),
            CircleType::App => Ok(UserHandle::from_hex(&self.id)?.into_bytes()),
            CircleType::User => Ok(UserHandle::from_hex(&self.id)?.into_bytes()),
        }
    }
}

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
    fn get_member(&self, id: CircleHandle) -> anyhow::Result<Option<CircleEntry>> {
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

    #[frb(sync)]
    fn get_members(&self) -> Vec<CircleEntry> {
        match self {
            Self::App(a) => a.blocking_read().get_members(),
            Self::Circle(c) => c.blocking_read().get_members(),
            Self::User(u) => u.blocking_read().get_members(),
        }
    }

    fn validate(&self) -> anyhow::Result<bool> {
        match self {
            Self::App(a) => a.blocking_read().validate(),
            Self::Circle(c) => c.blocking_read().validate(),
            Self::User(u) => u.blocking_read().validate(),
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

pub type ParentCache<'a> = BTreeMap<(String, UserHandle), &'a CircleWithMembers>;

impl CircleWithMembers {
    fn get_parent_vec(&self, cache: &ParentCache) -> Result<Option<Vec<(String, UserHandle)>>> {
        match self.get_parent_tuple()? {
            None => return Ok(None),
            Some(parent) => {
                let mut out = vec![parent];

                let mut prev = None;
                while let Some(np) = cache.get(out.last().unwrap()) {
                    if prev == Some(np) {
                        break;
                    }
                    prev = Some(np);
                    match np.get_parent_tuple()? {
                        Some(np) => out.push(np),
                        None => break,
                    }
                }

                Ok(Some(out))
            }
        }
    }

    fn get_id_vec(&self, cache: &ParentCache) -> Result<Option<Vec<(String, UserHandle)>>> {
        let parent = self.get_id_tuple()?;
        let mut out = vec![parent];

        let mut prev = None;
        while let Some(np) = cache.get(out.last().unwrap()) {
            if prev == Some(np) {
                break;
            }
            prev = Some(np);
            match np.get_parent_tuple()? {
                Some(np) => out.push(np),
                None => break,
            }
        }

        Ok(Some(out))
    }
}

impl PgpApp {
    pub fn circles_from_db(
        &self,
        members: Vec<CircleWithMembers>,
        users: bool,
        parent: Option<CircleHandle>,
        all: bool,
    ) -> Result<Vec<CircleOr>> {
        let out = CircleOr::get_parent_cache(&members)?;
        let parent = match parent {
            Some(parent) => out
                .get(&(
                    parent.circle_type.get_type_str().to_owned(),
                    UserHandle::RawBytes(parent.get_bytes()?),
                ))
                .map(|v| {
                    let v = v.get_parent_tuple().unwrap();
                    println!("get_parent_vec={out:?}");
                    v
                })
                .flatten(),
            None => None,
        };
        println!("parent = {parent:?}");

        let res = self.get_children(&out, &members, parent, &None, all)?;

        let res = res
            .into_iter()
            .map(|(_, v)| v)
            .flat_map(|v| v.content.into_option())
            .filter(|p| match p {
                CircleOr::User(_) => users,
                _ => true,
            })
            .collect();

        // println!("get! {res:#?}");
        Ok(res)
    }

    fn get_children(
        &self,
        members: &ParentCache,
        actual: &Vec<CircleWithMembers>,
        parent: Option<(String, UserHandle)>,
        start: &Option<CircleHandle>,
        all: bool,
    ) -> Result<Vec<(CircleHandle, TagOr)>> {
        self.get_children_parent(members, actual, parent, start, all)
    }
    fn get_children_parent(
        &self,
        members: &ParentCache,
        actual: &Vec<CircleWithMembers>,
        parent: Option<(String, UserHandle)>,
        start: &Option<CircleHandle>,
        all: bool,
    ) -> Result<Vec<(CircleHandle, TagOr)>> {
        // log::error!("get_children_parent {parent:?}");
        let mut out = Vec::new();

        for item in actual {
            // log::error!("for item in actual {item:?}");
            let pv = item.get_parent_tuple()?;
            // log::error!("get_parent_vec {}", pv.is_none());

            if pv != parent && !all {
                // println!("skipping pv={pv:?} parent={parent:?}");
                continue;
            }
            println!(
                "not skipping parent={parent:?} child={} type={}",
                UserHandle::RawBytes(item.get_id()?.to_owned()).name(),
                item.circle_type
            );

            let mut handle = item.get_id_userhandle()?;
            // log::error!("attempting get key");
            match self.get_key_from_fingerprint(&handle) {
                Ok(key) => match key.ids.first() {
                    Some(id) => handle.set_name(id.clone()),
                    None => (),
                },
                Err(err) => log::error!("failed to fetch key {err}"),
            }
            // log::error!("get key complete");
            // println!("get_children_parent {item:?}");
            match item.circle_type.as_ref() {
                "user" => {
                    let handle = CircleOr::User(RustAutoOpaque::new(handle));
                    out.push((
                        handle.handle(),
                        TagOr {
                            content: MaybeDeleted::Member(handle),
                            tag: item.get_tag()?,
                        },
                    ));
                }
                "circle" => {
                    let mut circle =
                        Circle::new_mut(item.get_id()?, item.get_author()?, None, self.clone())?;

                    let n = item.get_id_tuple()?;

                    circle.inner.members = self
                        .get_children_parent(members, actual, Some(n), start, false)?
                        .into_iter()
                        .flat_map(|(_, u)| u.content.into_option().map(|u| u.handle()))
                        .collect();

                    // circle.update_digest();
                    println!(
                        "pushing circle id={} actual={} members={}",
                        UserHandle::RawBytes(circle.get_id().to_owned()).name(),
                        UserHandle::RawBytes(item.get_id()?.to_owned()).name(),
                        circle.get_members().len()
                    );

                    circle.validate()?;
                    let circle = CircleOr::Circle(RustAutoOpaque::new(circle));

                    out.push((
                        circle.handle(),
                        TagOr {
                            content: MaybeDeleted::Member(circle),
                            tag: item.get_tag()?,
                        },
                    ));
                }
                "app" => {
                    let mut app =
                        CircleApp::new_empty(item.get_author()?, item.sig.clone(), self.clone())?;

                    let n = item.get_id_tuple()?;

                    app.inner.children = self
                        .get_children_parent(members, actual, Some(n), start, false)?
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
                    app.validate()?;
                    let id = CircleHandle {
                        id: app.id_hex(),
                        circle_type: CircleType::App,
                    };
                    let app = if item.deleted.unwrap_or_default() {
                        println!("app with members {:?}", app.inner.children);
                        MaybeDeleted::Deleted(item.get_id_userhandle()?)
                    } else {
                        MaybeDeleted::Member(CircleOr::App(RustAutoOpaque::new(app)))
                    };

                    out.push((
                        id,
                        TagOr {
                            content: app,
                            tag: item.get_tag()?,
                        },
                    ));
                }
                _ => return Err(InternalErr::InvalidCircleType(item.circle_type.clone())),
            }
        }
        Ok(out)
    }
}

impl CircleOr {
    pub(crate) fn empty() -> Self {
        Self::User(RustAutoOpaque::new(UserHandle::RawBytes(vec![])))
    }

    pub fn add(&self, circle: &CircleOr, tag: MemberTag, db: &PgpApp) -> anyhow::Result<()> {
        match self {
            CircleOr::Circle(c) => {
                let mut inner = c.blocking_write();
                inner.inner.members.insert(circle.handle());
                inner.update_digest()?;
                inner.to_db(&db.get_db())?;
            }
            CircleOr::App(a) => {
                let mut inner = a.blocking_write();

                match circle {
                    CircleOr::Circle(c) => inner.add_circle(c.blocking_read().clone(), tag)?,
                    CircleOr::App(a) => inner.add_app(a.blocking_read().clone(), tag)?,
                    CircleOr::User(u) => inner.add_user(u.blocking_read().clone(), tag)?,
                };
                inner.to_db(&db.get_db())?;
            }
            CircleOr::User(_) => (),
        }

        Ok(())
    }

    #[frb(sync)]
    pub fn handle(&self) -> CircleHandle {
        CircleHandle {
            id: self.id_hex(),
            circle_type: self.get_type(),
        }
    }

    pub(crate) fn db_type(&self) -> String {
        match self {
            CircleOr::App(_) => "app".to_owned(),
            CircleOr::User(_) => "user".to_owned(),
            CircleOr::Circle(_) => "circle".to_owned(),
        }
    }

    #[frb(sync)]
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

    fn get_parent_cache(members: &Vec<CircleWithMembers>) -> Result<ParentCache> {
        let mut out = BTreeMap::new();

        for member in members {
            out.insert(
                (
                    member.circle_type.clone(),
                    UserHandle::RawBytes(member.get_id()?),
                ),
                member,
            );
        }

        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CircleEntry {
    pub id: CircleHandle,
    pub content: Option<CircleOr>,
    pub tag: Option<MemberTag>,
}

impl CircleEntry {
    pub(crate) fn from_app_member(member: AppMember, id: CircleHandle) -> Self {
        Self {
            id,
            content: member.member.into_option(),
            tag: Some(member.tag),
        }
    }

    pub(crate) fn from_circle_or(circleor: CircleOr) -> Self {
        Self {
            id: circleor.handle(),
            content: Some(circleor),
            tag: None,
        }
    }
}

impl CircleType {
    fn get_type_str(&self) -> &'_ str {
        match self {
            CircleType::App => "app",
            CircleType::Circle => "circle",
            CircleType::User => "user",
        }
    }

    fn get_type_u8(&self) -> u8 {
        match self {
            CircleType::User => 0,
            CircleType::Circle => 1,
            CircleType::App => 2,
        }
    }

    pub fn from_str(s: &str) -> anyhow::Result<CircleType> {
        match s {
            "app" => Ok(CircleType::App),
            "user" => Ok(CircleType::User),
            "circle" => Ok(CircleType::Circle),
            _ => Err(anyhow!(InternalErr::InvalidMemberTag)),
        }
    }
}

pub trait CircleLike {
    fn iter_members(&self, sink: StreamSink<CircleEntry>);
    #[frb(sync)]
    fn get_member(&self, id: CircleHandle) -> anyhow::Result<Option<CircleEntry>>;
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
    fn validate(&self) -> anyhow::Result<bool>;
    fn from_db(db: Vec<CircleWithMembers>) -> Self
    where
        Self: Sized,
    {
        panic!("not implemented")
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[frb(non_opaque)]
pub enum CircleType {
    User,
    Circle,
    App,
}

// #[frb(opaque)]
// pub struct GenericCircle<'a>(Box<dyn CircleLike + Send + Sync + 'a>);

// impl<'a> GenericCircle<'a> {
//     pub fn new<T>(inner: T) -> GenericCircle<'a>
//     where
//         T: CircleLike + Send + Sync + 'a,
//     {
//         Self(Box::new(inner))
//     }
// }

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
    fn get_member(&self, id: CircleHandle) -> anyhow::Result<Option<CircleEntry>> {
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

    fn validate(&self) -> anyhow::Result<bool> {
        (*self).validate()
    }
}

// impl<'a> CircleLike for GenericCircle<'a> {
//     #[frb(sync)]
//     fn get_id(&self) -> Vec<u8> {
//         self.0.get_id()
//     }

//     #[frb(sync)]
//     fn get_id_userhandle(&self) -> UserHandle {
//         self.0.get_id_userhandle()
//     }

//     #[frb(sync)]
//     fn get_member(&self, id: UserHandle) -> Option<CircleEntry> {
//         self.0.get_member(id)
//     }

//     fn iter_members(&self, sink: StreamSink<CircleEntry>) {
//         self.0.iter_members(sink);
//     }

//     fn verify(&self) -> anyhow::Result<bool> {
//         self.0.verify()
//     }

//     #[frb(sync)]
//     fn get_type(&self) -> CircleType {
//         self.0.get_type()
//     }

//     fn insert(&self, db: &SqliteDb) -> anyhow::Result<()> {
//         self.0.insert(db)
//     }

//     #[frb(sync)]
//     fn get_members(&self) -> Vec<CircleEntry> {
//         self.0.get_members()
//     }

//     fn validate(&self) -> anyhow::Result<bool> {
//         self.0.validate()
//     }
// }

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

impl PgpApp {
    pub fn get_circles_for_parent(&self, parent: &CircleHandle) -> Result<Vec<CircleOr>> {
        let v = self
            .get_db()
            .get_circles_for_parent(&parent.id, parent.circle_type.get_type_str())?;

        self.circles_from_db(v, false, Some(parent.clone()), false)
    }

    pub fn get_circle_by_id(&self, id: &CircleHandle) -> Result<Option<CircleOr>> {
        println!("get_circle_by_id id={}", id.id);
        let v = self
            .get_db()
            .get_circles_by_id(&id.id, &id.circle_type.get_type_str())?;

        println!("v={v:#?}");
        println!("id: {id:?} {}", id.circle_type.get_type_str());

        let out = self.circles_from_db(v, true, Some(id.clone()), false)?;
        println!("out={out:?}");
        Ok(out.into_iter().find(|p| {
            println!("checking {id:?} {:?}", p.handle());
            p.handle() == *id
        }))
    }

    pub fn get_all_circle_ids(&self) -> Result<Vec<String>> {
        Ok(self
            .get_db()
            .get_all_circle_ids()?
            .into_iter()
            .map(|v| v.id)
            .collect())
    }
}

#[cfg(test)]
mod test {
    use crate::api::pgp::circles::CircleLike;
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
        let out = app.pgp.db.get_circle_by_id(&id, "user").unwrap();
        assert!(!out.is_empty());
        let newcircle = app.circles_from_db(out, false, None, false).unwrap();
        assert!(newcircle.is_empty());
        //assert_eq!(user, newcircle[0]);
    }

    #[test]
    fn get_circle_roots() {
        let app = PgpApp::create(test_config("app")).unwrap();

        let v = UserHandle::from_hex("9FCF6558AC4927F1E7A43D80317375B449854036").unwrap();
        let user = CircleOr::User(RustAutoOpaque::new(v));
        user.to_db(&app.pgp.db).unwrap();
        let out = app.pgp.db.get_circle_roots().unwrap();
        assert!(!out.is_empty());
        let newcircle = app.circles_from_db(out, false, None, false).unwrap();
        assert!(newcircle.is_empty());
        //assert_eq!(user, newcircle[0]);
    }

    #[test]
    fn circle_store_read() {
        let app = PgpApp::create(test_config("app")).unwrap();

        let v = UserHandle::from_hex("9FCF6558AC4927F1E7A43D80317375B449854036").unwrap();
        let user = CircleOr::User(RustAutoOpaque::new(v));
        user.to_db(&app.pgp.db).unwrap();
        let circle = app.create_circle(vec![user]).unwrap();
        let circle = CircleOr::Circle(RustAutoOpaque::new(circle));
        circle.to_db(&app.pgp.db).unwrap();

        let out = app.pgp.db.get_circles_join().unwrap();
        println!("{out:?}");
        //   let out = app.pgp.db.get_circle_by_id(&id).unwrap();

        assert_eq!(out.len(), 2);

        let newcircle = app.circles_from_db(out, false, None, false).unwrap();
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
        circle.add_user(v.clone(), MemberTag::Merge).unwrap();
        circle.add_user(u.clone(), MemberTag::Merge).unwrap();
        let circle = CircleOr::App(RustAutoOpaque::new(circle));

        circle.to_db(&app.pgp.db).unwrap();

        let out = app.pgp.db.get_circles_join().unwrap();
        println!("{out:?}");
        // let out = app.pgp.db.get_circle_by_id(&id).unwrap();

        assert_eq!(out.len(), 3);

        let newcircle = app.circles_from_db(out, false, None, false).unwrap();
        assert!(!newcircle.is_empty());
        assert_eq!(newcircle.len(), 1);
        assert_eq!(circle.get_members(), newcircle[0].get_members());
    }

    #[test]
    fn get_parent_vec() {
        let app = PgpApp::create(test_config("app")).unwrap();
        let key = app
            .generate_key("test@example.com".to_owned())
            .generate()
            .unwrap();
        let v = UserHandle::from_hex("9FCF6558AC4927F1E7A43D80317375B449854036").unwrap();
        let u = UserHandle::from_hex("9FCF6558AC4927F1E7A43D80317375B449854037").unwrap();

        let mut circle = app.create_app(&key.cert.fingerprint).unwrap();
        circle.add_user(v.clone(), MemberTag::Merge).unwrap();
        circle.add_user(u.clone(), MemberTag::Merge).unwrap();
        let circle = CircleOr::App(RustAutoOpaque::new(circle));

        circle.to_db(&app.pgp.db).unwrap();

        let out = app.pgp.db.get_circles_join().unwrap();
        let cache = CircleOr::get_parent_cache(&out).unwrap();

        let child = cache
            .values()
            .find(|p| p.get_id().unwrap() == v.as_bytes())
            .unwrap();

        let parents = child.get_parent_vec(&cache).unwrap().unwrap();

        assert_eq!(parents.len(), 1);
        assert_eq!(
            parents,
            vec![("app".to_owned(), UserHandle::RawBytes(circle.get_id()))]
        );
    }

    #[test]
    fn get_recursive() {
        env_logger::init();
        let app = PgpApp::create(test_config("app")).unwrap();
        let key = app
            .generate_key("test@example.com".to_owned())
            .generate()
            .unwrap();

        let mut circle = app.create_app(&key.cert.fingerprint).unwrap();

        circle.add_app(circle.clone(), MemberTag::Merge).unwrap();

        let circle = CircleOr::App(RustAutoOpaque::new(circle));
        let parent = app.create_circle(vec![circle.clone()]).unwrap();

        let parent = CircleOr::Circle(RustAutoOpaque::new(parent));

        circle.to_db(&app.pgp.db).unwrap();

        parent.to_db(&app.pgp.db).unwrap();

        let out = app
            .pgp
            .db
            .get_circles_for_parent(&parent.id_hex(), &parent.db_type())
            .unwrap();

        let outcircle = app.circles_from_db(out, false, None, false).unwrap();

        assert_eq!(outcircle.len(), 1);

        // assert_eq!(outcircle[0], parent);
    }

    #[test]
    fn get_parent() {
        let app = PgpApp::create(test_config("app")).unwrap();
        let v = UserHandle::from_hex("9FCF6558AC4927F1E7A43D80317375B449854036").unwrap();
        let u = UserHandle::from_hex("9FCF6558AC4927F1E7A43D80317375B449854037").unwrap();
        let v = CircleOr::User(RustAutoOpaque::new(v.clone()));
        let u = CircleOr::User(RustAutoOpaque::new(u.clone()));
        u.to_db(&app.pgp.db).unwrap();
        v.to_db(&app.pgp.db).unwrap();
        let childcircle = app.create_circle(vec![]).unwrap();

        let childcircle = CircleOr::Circle(RustAutoOpaque::new(childcircle));

        let circle = app.create_circle(vec![childcircle.clone()]).unwrap();
        let circle = CircleOr::Circle(RustAutoOpaque::new(circle));

        let singledecoy = app.create_circle(vec![]).unwrap();
        let singledecoy = CircleOr::Circle(RustAutoOpaque::new(singledecoy));

        let parent = app
            .create_circle(vec![circle.clone(), singledecoy.clone()])
            .unwrap();
        let decoy = app.create_circle(vec![v, u]).unwrap();

        let decoy = CircleOr::Circle(RustAutoOpaque::new(decoy));

        let parent = CircleOr::Circle(RustAutoOpaque::new(parent));

        singledecoy.to_db(&app.pgp.db).unwrap();
        circle.to_db(&app.pgp.db).unwrap();

        childcircle.to_db(&app.pgp.db).unwrap();

        parent.to_db(&app.pgp.db).unwrap();
        decoy.to_db(&app.pgp.db).unwrap();

        println!("{:?}", parent.handle());
        for (name, circle) in [
            ("circle", &circle),
            ("childcircle", &childcircle),
            ("parent", &parent),
            ("decoy", &decoy),
        ] {
            println!("circle={name}, id={}", circle.id_hex());
        }
        for (name, circle) in [
            ("circle", circle),
            ("childcircle", childcircle),
            ("parent", parent),
            ("decoy", decoy),
        ] {
            println!("testing {name}: {} {:?}", circle.id_hex(), circle.handle());
            let out = app.get_circle_by_id(&circle.handle()).unwrap();

            assert!(out.is_some());
        }
    }

    #[test]
    fn get_parent_multiple() {
        let app = PgpApp::create(test_config("app")).unwrap();

        let v = UserHandle::from_hex("9FCF6558AC4927F1E7A43D80317375B449854036").unwrap();
        let v = CircleOr::User(RustAutoOpaque::new(v.clone()));
        v.to_db(&app.pgp.db).unwrap();
        let dummy = app.create_circle(vec![v]).unwrap();
        let dummy = CircleOr::Circle(RustAutoOpaque::new(dummy));

        let circle = app.create_circle(vec![dummy.clone()]).unwrap();
        let circle = CircleOr::Circle(RustAutoOpaque::new(circle));

        let parent = app.create_circle(vec![circle.clone()]).unwrap();

        let parent = CircleOr::Circle(RustAutoOpaque::new(parent));
        dummy.to_db(&app.pgp.db).unwrap();
        circle.to_db(&app.pgp.db).unwrap();
        parent.to_db(&app.pgp.db).unwrap();

        println!("{:?}", parent.handle());
        for (name, circle) in [("circle", &circle), ("parent", &parent), ("dummy", &dummy)] {
            println!("circle={name}, id={}", circle.id_hex());
        }
        for (name, circle) in [("circle", circle), ("parent", parent)] {
            let out = app.get_circle_by_id(&circle.handle()).unwrap();
            println!("testing {name}: {} {:?}", circle.id_hex(), circle.handle());
            assert!(!out.unwrap().get_members().is_empty());
        }
    }
}
