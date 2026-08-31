use std::{
    collections::{btree_map::Entry, BTreeMap},
    io::Write,
};

use anyhow::anyhow;
use flutter_rust_bridge::frb;
use lazy_static::lazy_static;
use sequoia_openpgp::{
    parse::{stream::DetachedVerifierBuilder, Parse},
    serialize::stream::{Message, Signer},
};
use sequoia_wot::store::StoreError;
use serde::{Deserialize, Serialize};
use std::io::Read;

use crate::{
    api::{
        db::{
            connection::{Crud, OnConflict},
            store::{CertDao, CircleData, CircleMembersData},
        },
        pgp::{
            circles::{
                circle::Circle, CircleEntry, CircleHandle, CircleLike, CircleOr, CircleType,
            },
            sign::PgpAppVerifier,
            UserHandle, POLICY,
        },
        PgpApp, PgpAppTrait, SqliteDb,
    },
    error::{InternalErr, Result},
    frb_generated::{RustAutoOpaque, StreamSink},
};

#[derive(Debug, Serialize, Deserialize, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum MemberTag {
    Merge = 1,
    Overwrite = 2,
    Delete = 3,
}

#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord)]
#[frb(non_opaque)]
pub struct NonOpaqueApp {
    pub members: Vec<AppMember>,
    pub owner: UserHandle,
    pub sig: Vec<u8>,
}

impl NonOpaqueApp {
    pub fn to_db(&self, db: &SqliteDb) -> anyhow::Result<()> {
        let entity = CircleData {
            id: self.owner.name(),
            circle_type: "app".to_owned(),
            author: Some(self.owner.name()),
            sig: Some(self.sig.clone()),
        };

        entity.insert_on_conflict_custom(
            db,
            OnConflict::Update,
            vec!["id", "circle_type"],
            vec!["author", "sig", "circle_type"],
        )?;

        for m in self.members.iter() {
            match m.member {
                MaybeDeleted::Deleted(ref v) => {
                    db.delete_circle_member(&v.id.name(), v.circle_type.get_type_str())?
                }
                MaybeDeleted::Member(_) => (),
            }

            let entity = CircleMembersData {
                circle_member_id: None,
                member_id: m.member.id_hex(),
                parent_id: self.owner.name(),
                deleted: Some(false),
                parent_type: "app".to_owned(),
                member_type: m.member.member_type(),
                tag: Some(m.tag.as_str().to_owned()),
            };

            entity.insert_on_conflict_custom(
                db,
                OnConflict::Update,
                vec!["member_id", "parent_id", "member_type", "parent_type"],
                vec!["tag", "deleted"],
            )?;
        }

        Ok(())
    }
}

impl AppMember {
    fn as_read<'a>(&'a self) -> impl std::io::Read + Send + Sync + 'a {
        self.member
            .option()
            .unwrap_or(&EMPTY)
            .as_read()
            .chain(self.tag.as_bytes())
    }
}

impl MemberTag {
    fn as_bytes<'a>(&'a self) -> &'a [u8] {
        match self {
            Self::Merge => &[1],
            Self::Overwrite => &[2],
            Self::Delete => &[3],
        }
    }

    fn as_str(&self) -> &str {
        match self {
            Self::Delete => "delete",
            Self::Merge => "merge",
            Self::Overwrite => "overwrite",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum MaybeDeleted {
    Member(CircleHandle),
    Deleted(CircleHandle),
}

impl MaybeDeleted {
    pub(crate) fn member_type(&self) -> String {
        match self {
            Self::Member(m) => match m.circle_type {
                CircleType::App => "app".to_owned(),
                CircleType::User => "user".to_owned(),
                CircleType::Circle => "circle".to_owned(),
            },
            Self::Deleted(d) => d.circle_type.get_type_str().to_owned(),
        }
    }
    fn option(&self) -> Option<&'_ CircleHandle> {
        match self {
            Self::Member(v) => Some(v),
            Self::Deleted(_) => None,
        }
    }

    pub(crate) fn delete(&self) -> MaybeDeleted {
        match self {
            MaybeDeleted::Member(m) => MaybeDeleted::Deleted(m.clone()),
            v => v.clone(),
        }
    }

    pub(crate) fn into_option(self) -> Option<CircleHandle> {
        match self {
            Self::Member(member) => Some(member),
            Self::Deleted(_) => None,
        }
    }

    #[frb(sync)]
    pub fn member(&self) -> Option<CircleHandle> {
        self.clone().into_option()
    }

    fn option_mut(&mut self) -> Option<&'_ mut CircleHandle> {
        match self {
            Self::Member(v) => Some(v),
            Self::Deleted(_) => None,
        }
    }

    fn is_none(&self) -> bool {
        match self {
            Self::Deleted(_) => true,
            Self::Member(_) => false,
        }
    }

    #[frb(sync)]
    fn id_hex(&self) -> String {
        match self {
            Self::Member(m) => m.id.name(),
            Self::Deleted(m) => m.id.name(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[frb(non_opaque)]
pub struct AppMember {
    pub member: MaybeDeleted,
    pub tag: MemberTag,
}

// TODO: fixd
lazy_static! {
    static ref EMPTY: CircleHandle = CircleHandle {
        id: UserHandle::RawBytes(vec![]),
        circle_type: CircleType::User
    };
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[frb(opaque)]
pub(crate) struct CircleAppInner {
    pub(crate) owner: UserHandle,
    pub(crate) children: BTreeMap<CircleHandle, AppMember>,
    pub(crate) sig: Vec<u8>,
}

#[derive(Debug, Clone)]
#[frb(opaque)]
pub struct CircleApp {
    pub(crate) inner: CircleAppInner,
    pub(crate) pgp: PgpApp,
}

impl PartialEq for CircleApp {
    fn eq(&self, other: &Self) -> bool {
        self.inner.eq(&other.inner)
    }
}

impl PartialOrd for CircleApp {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.inner.partial_cmp(&other.inner)
    }
}

impl Eq for CircleApp {}

impl Ord for CircleApp {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.inner.cmp(&other.inner)
    }
}

impl CircleLike for CircleApp {
    #[frb(sync)]
    fn get_id(&self) -> Vec<u8> {
        self.inner.owner.as_bytes().to_owned()
    }

    #[frb(sync)]
    fn get_id_userhandle(&self) -> UserHandle {
        self.inner.owner.clone()
    }

    fn iter_members(&self, sink: StreamSink<CircleEntry>) {
        for (id, member) in self.inner.children.iter() {
            if let Ok(Some(v)) = self.pgp.get_circle_by_id(id) {
                sink.add(CircleEntry::from_circle_or_tag(v, member.tag))
                    .unwrap();
            }
        }
    }

    #[frb(sync)]
    fn get_member(&self, id: &CircleHandle) -> anyhow::Result<Option<CircleEntry>> {
        let res = self.inner.children.get(&id).and_then(|t| {
            t.member.option().and_then(|v| {
                self.pgp
                    .get_circle_by_id(v)
                    .ok()
                    .and_then(|v| v)
                    .map(|v| CircleEntry::from_circle_or_tag(v, t.tag))
            })
        });
        Ok(res)
    }

    fn verify(&self) -> anyhow::Result<bool> {
        let res = self.pgp.verify_app(self).is_ok();
        Ok(res)
    }

    #[frb(sync)]
    fn get_type(&self) -> super::CircleType {
        CircleType::App
    }

    fn insert(&self, db: &SqliteDb) -> anyhow::Result<()> {
        self.to_db(db)
    }

    #[frb(sync)]
    fn get_members(&self) -> Vec<CircleEntry> {
        self.inner
            .children
            .iter()
            .flat_map(|(id, v)| {
                self.pgp
                    .get_circle_by_id(id)
                    .ok()
                    .and_then(|circ| circ.map(|circ| CircleEntry::from_circle_or_tag(circ, v.tag)))
            })
            .collect()
    }

    fn validate(&self) -> anyhow::Result<bool> {
        self.pgp.verify_app(self)
    }

    #[frb(sync)]
    fn handle(&self) -> CircleHandle {
        CircleHandle {
            id: self.get_id_userhandle(),
            circle_type: CircleType::App,
        }
    }

    #[frb(sync)]
    fn get_owner(&self) -> Option<UserHandle> {
        Some(self.inner.owner.clone())
    }
}

impl CircleApp {
    pub fn to_db(&self, db: &SqliteDb) -> anyhow::Result<()> {
        let entity = CircleData {
            id: self.inner.owner.name(),
            circle_type: "app".to_owned(),
            author: Some(self.inner.owner.name()),
            sig: Some(self.inner.sig.clone()),
        };
        entity.insert_on_conflict_custom(
            db,
            OnConflict::Update,
            vec!["id", "circle_type"],
            vec!["author", "sig", "circle_type"],
        )?;

        for CircleHandle { id, circle_type } in self.inner.children.keys() {
            if let CircleType::User = circle_type {
                let entity = CircleData {
                    id: id.name(),
                    circle_type: "user".to_owned(),
                    author: None,
                    sig: None,
                };
                entity.insert_on_conflict_custom(
                    db,
                    OnConflict::Ignore,
                    vec!["id", "circle_type"],
                    vec!["author", "sig", "circle_type"],
                )?;
            }
        }

        for member in self.inner.children.values() {
            match member.member {
                MaybeDeleted::Member(ref m) => {
                    let entity = CircleMembersData {
                        circle_member_id: None,
                        member_id: m.id.name(),
                        deleted: Some(false),
                        parent_type: "app".to_owned(),
                        parent_id: self.inner.owner.name(),
                        member_type: m.circle_type.get_type_str().to_owned(),
                        tag: Some(member.tag.as_str().to_owned()),
                    };

                    entity.insert_on_conflict_custom(
                        db,
                        OnConflict::Update,
                        vec!["member_id", "parent_id", "member_type", "parent_type"],
                        vec!["deleted", "tag"],
                    )?;
                }
                MaybeDeleted::Deleted(ref d) => {
                    let entity = CircleMembersData {
                        circle_member_id: None,
                        member_id: d.id.name(),
                        deleted: Some(true),
                        parent_type: "app".to_owned(),
                        parent_id: self.inner.owner.name(),
                        member_type: d.circle_type.get_type_str().to_owned(),
                        tag: Some("delete".to_owned()),
                    };
                    log::error!("deleted {entity:?}");

                    entity.insert_on_conflict_custom(
                        db,
                        OnConflict::Update,
                        vec!["member_id", "parent_id", "member_type", "parent_type"],
                        vec!["deleted", "tag"],
                    )?;
                }
            }
        }
        Ok(())
    }

    #[frb(sync)]
    pub fn update_tag(&mut self, id: &CircleHandle, tag: MemberTag) {
        if let Some(member) = self.inner.children.get_mut(id) {
            member.tag = tag;
        }
    }

    #[frb(sync)]
    pub fn consume_members(self) -> NonOpaqueApp {
        NonOpaqueApp {
            members: self.inner.children.into_values().collect(),
            owner: self.inner.owner,
            sig: self.inner.sig,
        }
    }

    #[frb(sync)]
    pub fn id_hex(&self) -> String {
        self.inner.owner.name()
    }

    // #[frb(sync)]
    // pub fn get_members(&self) -> Vec<AppMember> {
    //     self.inner.children.values().cloned().collect()
    // }

    pub(crate) fn new_empty(
        author: Option<UserHandle>,
        sig: Option<Vec<u8>>,
        pgp: PgpApp,
    ) -> Result<Self> {
        let (owner, sig) = match (author, sig) {
            (Some(owner), Some(sig)) => (owner, sig),
            _ => (UserHandle::RawBytes(vec![]), vec![]),
        };

        let res = Self {
            inner: CircleAppInner {
                owner,
                children: BTreeMap::new(),
                sig,
            },
            pgp,
        };

        Ok(res)
    }

    fn tag_reader<'a>(&'a self) -> Box<dyn std::io::Read + Send + Sync + 'a> {
        let v: &[u8] = &[];
        for (i, tag) in self.inner.children.values().enumerate() {
            let v = v.chain(tag.as_read());
            if i + 1 == self.inner.children.len() {
                return Box::new(v);
            }
        }
        Box::new(v)
    }

    pub fn is_member(&self, user: &CircleHandle) -> bool {
        self.inner.children.contains_key(user)
    }

    fn to_read<'a>(&'a self) -> impl std::io::Read + Send + Sync + 'a {
        self.inner.owner.as_bytes().chain(self.tag_reader())
    }

    fn resign(&mut self) -> anyhow::Result<()> {
        let mut out = Vec::new();
        {
            let cert = self
                .pgp
                .configured_privkey(&self.inner.owner, |v| v.for_signing())?;

            let message = Message::new(&mut out);

            let mut signer = Signer::new(message, cert)?.detached().build()?;

            signer.write_all(&self.inner.owner.as_bytes())?;
            signer.write_all(&[])?;
            signer.finalize()?;
        }
        self.inner.sig = out;
        Ok(())
    }

    pub fn remove(
        &mut self,
        handle: &CircleHandle,
        parent: &CircleHandle,
        delete: bool,
    ) -> anyhow::Result<()> {
        if delete {
            if let Some(child) = self.inner.children.get_mut(handle) {
                child.member = child.member.delete();
                child.tag = MemberTag::Delete;
            }
        } else {
            self.pgp.get_db().purge_circle_member(
                &handle.id.name(),
                handle.circle_type.get_type_str(),
                &parent.id.name(),
                parent.circle_type.get_type_str(),
            )?;
            self.inner.children.remove(handle);
        }
        self.resign()
    }

    pub fn add_circle(&mut self, circle: &Circle, tag: MemberTag) -> anyhow::Result<()> {
        let id = CircleHandle {
            id: circle.inner.id.clone(),
            circle_type: CircleType::Circle,
        };
        circle.to_db(&self.pgp.get_db())?;
        self.inner.children.insert(
            id,
            AppMember {
                member: match tag {
                    MemberTag::Delete => MaybeDeleted::Deleted(circle.handle()),
                    _ => MaybeDeleted::Member(circle.handle()),
                },
                tag,
            },
        );
        self.resign()
    }

    pub fn add_app(&mut self, app: &CircleApp, tag: MemberTag) -> anyhow::Result<()> {
        let id = CircleHandle {
            id: app.get_id_userhandle(),
            circle_type: CircleType::App,
        };
        app.to_db(&self.pgp.get_db())?;
        self.inner.children.insert(
            id,
            AppMember {
                member: match tag {
                    MemberTag::Delete => MaybeDeleted::Deleted(app.handle()),
                    _ => MaybeDeleted::Member(app.handle()),
                },
                tag,
            },
        );
        self.resign()
    }

    pub fn add_user(&mut self, user: &UserHandle, tag: MemberTag) -> anyhow::Result<()> {
        let id = CircleHandle {
            id: user.clone(),
            circle_type: CircleType::User,
        };
        user.to_db(&self.pgp.get_db())?;
        self.inner.children.insert(
            id,
            AppMember {
                member: match tag {
                    MemberTag::Delete => MaybeDeleted::Deleted(user.get_handle()),
                    _ => MaybeDeleted::Member(user.get_handle()),
                },
                tag,
            },
        );
        self.resign()
    }

    pub fn merge_both(&mut self, other: &mut CircleApp) -> anyhow::Result<()> {
        self.merge(other)?;
        other.merge(self)
    }

    pub fn merge(&mut self, other: &CircleApp) -> anyhow::Result<()> {
        for (id, entry) in other.inner.children.iter() {
            match self.inner.children.entry(id.to_owned()) {
                Entry::Occupied(mut ours) => match (ours.get().tag, entry.tag) {
                    (MemberTag::Delete, _) => {
                        let ours = ours.get_mut();
                        ours.tag = MemberTag::Delete;
                        // TODO: maybe handle member type here, circles use differednt
                        // userhandle types than apps?
                        ours.member = ours.member.delete();
                    }
                    (_, MemberTag::Delete) => {
                        let ours = ours.get_mut();
                        ours.tag = MemberTag::Delete;
                        ours.member = ours.member.delete();
                    }
                    (MemberTag::Overwrite, MemberTag::Overwrite) => {
                        // TODO: how to handle this
                    }
                    (MemberTag::Overwrite, _) => {}
                    (_, MemberTag::Overwrite) => {
                        ours.get_mut().member = entry.member.clone();
                    }
                    (MemberTag::Merge, MemberTag::Merge) => {
                        // if the id is the same, we have the same user or the same circle,
                        // but apps must be merged
                        if let (MaybeDeleted::Member(ours), MaybeDeleted::Member(theirs)) =
                            (&mut ours.get_mut().member, &entry.member)
                        {
                            // TODO: cycle detection here
                            match (
                                self.pgp.get_circle_by_id(ours)?,
                                self.pgp.get_circle_by_id(theirs)?,
                            ) {
                                (Some(CircleOr::App(ours)), Some(CircleOr::App(theirs))) => {
                                    ours.blocking_write().merge(&theirs.blocking_read())?
                                }
                                _ => (),
                            }
                        }
                    }
                },
                Entry::Vacant(vacent) => {
                    vacent.insert(entry.clone());
                }
            }
        }

        self.resign()?;
        Ok(())
    }
}

impl PgpApp {
    pub fn verify_app(&self, app: &CircleApp) -> anyhow::Result<bool> {
        let mut helper = PgpAppVerifier::from_app(self);
        let mut verifier = match DetachedVerifierBuilder::from_bytes(&app.inner.sig)?
            .mapping(true)
            .with_policy(&POLICY, None, &mut helper)
        {
            Ok(v) => Ok(v),
            Err(e) => Err(match e.downcast() {
                Ok(StoreError::NotFound(_)) => {
                    return Ok(false);
                }

                Err(e) => e,
                Ok(e) => anyhow!(e),
            }),
        }?;

        let read = app.to_read();

        verifier.verify_reader(read)?;

        Ok(true)
    }

    pub fn create_app(&self, owner: &UserHandle) -> anyhow::Result<CircleApp> {
        let mut out = Vec::new();
        let children = BTreeMap::new();
        {
            let cert = self.configured_privkey(&owner, |v| v.for_signing())?;

            let message = Message::new(&mut out);

            let mut signer = Signer::new(message, cert)?.detached().build()?;

            signer.write_all(owner.as_bytes())?;
            signer.write_all(&[])?;
            signer.finalize()?;
        }

        Ok(CircleApp {
            inner: CircleAppInner {
                owner: owner.clone(),
                children,
                sig: out,
            },
            pgp: self.clone(),
        })
    }
}

#[cfg(test)]
mod test {
    use crate::{
        api::{
            pgp::{
                circles::{app::MemberTag, CircleLike, CircleOr},
                test_config,
            },
            PgpApp, PgpAppTrait,
        },
        frb_generated::RustAutoOpaque,
    };

    #[test]
    fn create_signed_app() {
        let app = PgpApp::create(test_config("app")).unwrap();
        let key = app
            .generate_key("test@example.com".to_owned())
            .generate()
            .unwrap();

        let author = key.cert.fingerprint;

        let app = app.create_app(&author).unwrap();
        assert_eq!(author.name(), app.inner.owner.name())
    }

    #[test]
    fn verify_signed_app() {
        let app = PgpApp::create(test_config("app")).unwrap();

        let key = app
            .generate_key("test@example.com".to_owned())
            .generate()
            .unwrap();

        let author = key.cert.fingerprint;

        let a = app.create_app(&author).unwrap();
        let res = app.verify_app(&a).unwrap();
        assert!(res);
    }

    #[test]
    fn merge_apps() {
        let service = PgpApp::create(test_config("app")).unwrap();

        let key = service
            .generate_key("test@example.com".to_owned())
            .generate()
            .unwrap();

        let author = key.cert.fingerprint;

        let mut a = service.create_app(&author).unwrap();
        let a2 = service.create_app(&author).unwrap();
        a.merge(&a2).unwrap();
        let res = service.verify_app(&a).unwrap();
        assert!(res);
        let res = service.verify_app(&a2).unwrap();
        assert!(res);
    }

    #[test]
    fn merge_apps_both() {
        let service = PgpApp::create(test_config("app")).unwrap();

        let key = service
            .generate_key("test@example.com".to_owned())
            .generate()
            .unwrap();

        let author = key.cert.fingerprint;

        let mut a = service.create_app(&author).unwrap();
        let mut a2 = service.create_app(&author).unwrap();
        a.merge_both(&mut a2).unwrap();
        let res = service.verify_app(&a).unwrap();
        assert!(res);
        let res = service.verify_app(&a2).unwrap();
        assert!(res);
    }

    #[test]
    fn merge_apps_members() {
        let service = PgpApp::create(test_config("app")).unwrap();

        let key = service
            .generate_key("test@example.com".to_owned())
            .generate()
            .unwrap();

        let author = key.cert.fingerprint;

        let mut a = service.create_app(&author).unwrap();
        let mut a2 = service.create_app(&author).unwrap();
        let circ = service.create_circle(vec![]).unwrap();
        a2.add_circle(&circ, MemberTag::Merge).unwrap();
        a.merge_both(&mut a2).unwrap();
        let res = service.verify_app(&a).unwrap();
        assert!(res);
        let res = service.verify_app(&a2).unwrap();
        assert!(res);

        assert_eq!(a.inner.children.len(), 1);
        assert_eq!(a.inner.children.len(), 1);
        assert_eq!(a.inner.children, a2.inner.children);
    }

    #[test]
    fn app_contains_itself() {
        let service = PgpApp::create(test_config("app")).unwrap();

        let key = service
            .generate_key("test@example.com".to_owned())
            .generate()
            .unwrap();

        let mut app = service.create_app(&key.cert.fingerprint).unwrap();
        app.add_app(&app.clone(), MemberTag::Merge).unwrap();
        let app = CircleOr::App(RustAutoOpaque::new(app));
        app.to_db(&service.get_db()).unwrap();

        let _ = app.get_members();

        // let members = service.get_db().get_circles_join().unwrap();
        // let test = service.circles_from_db(members, false, None, true).unwrap();
        // for circle in test {
        //     if let CircleOr::App(ref app) = circle {
        //         let clone = app.blocking_read().clone();
        //         let mut app = app.blocking_write();
        //         app.add_app(clone, MemberTag::Merge).unwrap();
        //     }

        //     circle.to_db(&service.get_db()).unwrap();
        // }

        // let members = service.get_db().get_circles_join().unwrap();
        // let test = service.circles_from_db(members, false, None, true).unwrap();
    }

    #[test]
    fn merge_apps_delete() {
        let service = PgpApp::create(test_config("app")).unwrap();

        let key = service
            .generate_key("test@example.com".to_owned())
            .generate()
            .unwrap();

        let author = key.cert.fingerprint;

        let mut a = service.create_app(&author).unwrap();
        let circ = service.create_circle(vec![]).unwrap();
        let mut a2 = service.create_app(&author).unwrap();
        a2.add_circle(&circ, MemberTag::Delete).unwrap();
        a.merge_both(&mut a2).unwrap();
        let res = service.verify_app(&a).unwrap();
        assert!(res);
        let res = service.verify_app(&a2).unwrap();
        assert!(res);
        assert_eq!(a.inner.children.len(), 1);
        assert_eq!(a.inner.children.len(), 1);
        assert_eq!(
            a.inner.children.values().next().unwrap().tag,
            MemberTag::Delete
        );
        assert_eq!(
            a2.inner.children.values().next().unwrap().tag,
            MemberTag::Delete
        );

        assert!(a.inner.children.values().next().unwrap().member.is_none());
        assert!(a2.inner.children.values().next().unwrap().member.is_none());
        assert_eq!(a.inner.children, a2.inner.children);
    }
}
