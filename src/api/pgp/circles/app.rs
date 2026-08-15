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
            circles::{circle::Circle, CircleEntry, CircleLike, CircleOr, CircleType},
            sign::PgpAppVerifier,
            UserHandle, POLICY,
        },
        PgpApp, SqliteDb,
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

        entity.insert_on_conflict_custom(db, OnConflict::Update, vec!["id", "circle_type"])?;

        for m in self.members.iter() {
            match m.member {
                MaybeDeleted::Deleted(ref v) => db.delete_circle_member(&v.name())?,
                MaybeDeleted::Member(ref v) => v.to_db(db)?,
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
            )?;
        }

        Ok(())
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum MaybeDeleted {
    Member(CircleOr),
    Deleted(UserHandle),
}

impl MaybeDeleted {
    pub(crate) fn member_type(&self) -> String {
        match self {
            Self::Member(m) => match m {
                CircleOr::App(_) => "app".to_owned(),
                CircleOr::User(_) => "user".to_owned(),
                CircleOr::Circle(_) => "circle".to_owned(),
            },
            Self::Deleted(_) => "TODO DELETED".to_owned(),
        }
    }
    fn option(&self) -> Option<&'_ CircleOr> {
        match self {
            Self::Member(v) => Some(v),
            Self::Deleted(_) => None,
        }
    }

    pub(crate) fn delete(&self) -> MaybeDeleted {
        match self {
            MaybeDeleted::Member(m) => MaybeDeleted::Deleted(m.clone().get_userhandle()),
            v => v.clone(),
        }
    }

    pub(crate) fn into_option(self) -> Option<CircleOr> {
        match self {
            Self::Member(member) => Some(member),
            Self::Deleted(_) => None,
        }
    }

    #[frb(sync)]
    pub fn member(&self) -> Option<CircleOr> {
        self.clone().into_option()
    }

    fn option_mut(&mut self) -> Option<&'_ mut CircleOr> {
        match self {
            Self::Member(v) => Some(v),
            Self::Deleted(_) => None,
        }
    }

    #[frb(sync)]
    fn id_hex(&self) -> String {
        match self {
            Self::Member(m) => m.id_hex(),
            Self::Deleted(m) => m.name(),
        }
    }

    fn is_none(&self) -> bool {
        match self {
            Self::Deleted(_) => true,
            Self::Member(_) => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[frb(non_opaque)]
pub struct AppMember {
    pub member: MaybeDeleted,
    pub tag: MemberTag,
}

fn generic_read() -> impl std::io::Read + 'static {
    let v = &[];
    v.as_slice()
}

lazy_static! {
    static ref EMPTY: CircleOr = CircleOr::empty();
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[frb(opaque)]
pub(crate) struct CircleAppInner {
    pub(crate) owner: UserHandle,
    pub(crate) children: BTreeMap<Vec<u8>, AppMember>,
    pub(crate) sig: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[frb(opaque)]
pub struct CircleApp {
    #[serde(flatten)]
    pub(crate) inner: CircleAppInner,
    #[serde(deserialize_with = "none", skip)]
    pgp: Option<PgpApp>,
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
            let id = UserHandle::RawBytes(id.clone());
            sink.add(CircleEntry::from_app_member(member.clone(), id))
                .unwrap();
        }
    }

    #[frb(sync)]
    fn get_member(&self, id: UserHandle) -> Option<CircleEntry> {
        self.inner
            .children
            .get(id.as_bytes())
            .cloned()
            .map(|v| CircleEntry::from_app_member(v, id))
    }

    fn verify(&self) -> anyhow::Result<bool> {
        let res = self
            .pgp
            .as_ref()
            .ok_or(InternalErr::MissingPgpApp)?
            .verify_app(self)
            .is_ok();
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
            .map(|(id, v)| {
                CircleEntry::from_app_member(v.clone(), UserHandle::RawBytes(id.clone()))
            })
            .collect()
    }

    fn validate(&self) -> anyhow::Result<bool> {
        match self.pgp {
            None => Ok(false),
            Some(ref pgp) => pgp.verify_app(self),
        }
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
        entity.insert_on_conflict_custom(db, OnConflict::Update, vec!["id", "circle_type"])?;

        for member in self.inner.children.values() {
            match member.member {
                MaybeDeleted::Member(ref m) => {
                    m.to_db(db)?;
                    let entity = CircleMembersData {
                        circle_member_id: None,
                        member_id: m.id_hex(),
                        deleted: Some(false),
                        parent_type: "app".to_owned(),
                        parent_id: self.inner.owner.name(),
                        member_type: m.db_type(),
                        tag: Some(member.tag.as_str().to_owned()),
                    };

                    entity.insert_on_conflict_custom(
                        db,
                        OnConflict::Update,
                        vec!["member_id", "parent_id", "member_type", "parent_type"],
                    )?;
                }
                MaybeDeleted::Deleted(ref d) => {
                    let entity = CircleMembersData {
                        circle_member_id: None,
                        member_id: d.name(),
                        deleted: Some(true),
                        parent_type: "app".to_owned(),
                        parent_id: self.inner.owner.name(),
                        member_type: "TODO DELETED".to_owned(),
                        tag: Some(member.tag.as_str().to_owned()),
                    };

                    entity.insert_on_conflict_custom(
                        db,
                        OnConflict::Update,
                        vec!["member_id", "parent_id", "member_type", "parent_type"],
                    )?;
                }
            }
        }
        Ok(())
    }

    #[frb(sync)]
    pub fn update_tag(&mut self, id: &UserHandle, tag: MemberTag) {
        if let Some(member) = self.inner.children.get_mut(id.as_bytes()) {
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

    pub(crate) fn new_empty(author: Option<UserHandle>, sig: Option<Vec<u8>>) -> Result<Self> {
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
            pgp: None,
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

    pub fn is_member(&self, user: &UserHandle) -> bool {
        self.inner
            .children
            .values()
            .flat_map(|v| v.member.option())
            .any(|v| v.is_member(user))
    }

    pub fn set_pgp(&mut self, app: PgpApp) {
        self.pgp = Some(app);
    }

    fn to_read<'a>(&'a self) -> impl std::io::Read + Send + Sync + 'a {
        self.inner.owner.as_bytes().chain(self.tag_reader())
    }

    fn resign(&mut self) -> anyhow::Result<()> {
        let mut out = Vec::new();
        {
            let cert = self
                .pgp
                .as_ref()
                .ok_or(InternalErr::MissingPgpApp)?
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

    pub fn add_circle(&mut self, circle: Circle, tag: MemberTag) -> anyhow::Result<()> {
        let id = circle.inner.id.as_bytes().to_owned();
        self.inner.children.insert(
            id.clone(),
            AppMember {
                member: match tag {
                    MemberTag::Delete => MaybeDeleted::Deleted(circle.get_id_userhandle()),
                    _ => MaybeDeleted::Member(CircleOr::Circle(RustAutoOpaque::new(circle))),
                },
                tag,
            },
        );
        self.resign()
    }

    pub fn add_app(&mut self, app: CircleApp, tag: MemberTag) -> anyhow::Result<()> {
        let id = app.inner.owner.as_bytes().to_owned();
        self.inner.children.insert(
            id.clone(),
            AppMember {
                member: match tag {
                    MemberTag::Delete => MaybeDeleted::Deleted(app.get_id_userhandle()),
                    _ => MaybeDeleted::Member(CircleOr::App(RustAutoOpaque::new(app))),
                },
                tag,
            },
        );
        self.resign()
    }

    pub fn add_user(&mut self, user: UserHandle, tag: MemberTag) -> anyhow::Result<()> {
        self.inner.children.insert(
            user.as_bytes().to_owned(),
            AppMember {
                member: match tag {
                    MemberTag::Delete => MaybeDeleted::Deleted(user),
                    _ => MaybeDeleted::Member(CircleOr::User(RustAutoOpaque::new(user))),
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
                        if let (
                            MaybeDeleted::Member(CircleOr::App(ours)),
                            MaybeDeleted::Member(CircleOr::App(theirs)),
                        ) = (&mut ours.get_mut().member, &entry.member)
                        {
                            ours.blocking_write().merge(&theirs.blocking_read())?;
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
            pgp: Some(self.clone()),
        })
    }
}

#[cfg(test)]
mod test {
    use crate::api::{
        pgp::{circles::app::MemberTag, test_config},
        PgpApp, PgpAppTrait,
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
        a2.add_circle(circ, MemberTag::Merge).unwrap();
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
        a2.add_circle(circ, MemberTag::Delete).unwrap();
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
