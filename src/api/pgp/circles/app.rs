use std::{
    collections::{btree_map::Entry, BTreeMap},
    io::Write,
};

use anyhow::anyhow;
use flutter_rust_bridge::frb;
use sequoia_openpgp::{
    parse::{stream::DetachedVerifierBuilder, Parse},
    serialize::stream::{Message, Signer},
};
use sequoia_wot::store::StoreError;
use serde::{Deserialize, Serialize};
use std::io::Read;

use crate::api::{
    pgp::{circles::CircleOr, sign::PgpAppVerifier, UserHandle, POLICY},
    PgpApp,
};

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum MemberTag {
    Merge = 1,
    Overwrite = 2,
    Delete = 3,
}

impl MemberTag {
    fn as_bytes<'a>(&'a self) -> &'a [u8] {
        match self {
            Self::Merge => &[1],
            Self::Overwrite => &[2],
            Self::Delete => &[3],
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
#[frb(opaque)]
pub struct AppMember {
    member: CircleOr,
    tag: MemberTag,
}

impl AppMember {
    fn get_id(&self) -> &'_ [u8] {
        self.member.get_id()
    }

    fn as_read<'a>(&'a self) -> impl std::io::Read + Send + Sync + 'a {
        self.member.as_bytes().chain(self.tag.as_bytes())
    }
}
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
#[frb(opaque)]
pub(crate) struct CircleAppInner {
    pub(crate) owner: UserHandle,
    pub(crate) children: BTreeMap<Vec<u8>, AppMember>,
    pub(crate) sig: Vec<u8>,
}

#[derive(Clone)]
#[frb(opaque)]
pub struct CircleApp {
    pub(crate) inner: CircleAppInner,
    pgp: PgpApp,
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

impl CircleApp {
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
            .any(|v| v.member.is_member(user))
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

    pub fn add_members(&mut self, members: Vec<AppMember>) -> anyhow::Result<()> {
        for member in members {
            self.inner
                .children
                .insert(member.get_id().to_owned(), member);
        }
        self.resign()
    }

    pub fn set_members(&mut self, members: Vec<AppMember>) -> anyhow::Result<()> {
        self.inner.children.clear();
        self.add_members(members)
    }

    pub fn merge_both(&mut self, other: &mut CircleApp) -> anyhow::Result<()> {
        self.merge(other)?;
        other.merge(self)
    }

    pub fn merge(&mut self, other: &CircleApp) -> anyhow::Result<()> {
        for (id, entry) in other.inner.children.iter() {
            match self.inner.children.entry(id.to_owned()) {
                Entry::Occupied(mut ours) => match (ours.get().tag, entry.tag) {
                    (MemberTag::Delete, MemberTag::Delete) => (),
                    (MemberTag::Delete, _) => {}
                    (_, MemberTag::Delete) => {
                        ours.get_mut().tag = MemberTag::Delete;
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
                        if let (CircleOr::App(ours), CircleOr::App(theirs)) =
                            (&mut ours.get_mut().member, &entry.member)
                        {
                            ours.merge(theirs)?;
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

    pub fn create_app(&self, owner: UserHandle) -> anyhow::Result<CircleApp> {
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
                owner,
                children,
                sig: out,
            },
            pgp: self.clone(),
        })
    }
}

#[cfg(test)]
mod test {
    use crate::api::{pgp::test_config, PgpApp, PgpAppTrait};

    #[test]
    fn create_signed_app() {
        let app = PgpApp::create(test_config("app")).unwrap();
        let key = app
            .generate_key("test@example.com".to_owned())
            .generate()
            .unwrap();

        let author = key.cert.fingerprint;

        let app = app.create_app(author.clone()).unwrap();
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

        let a = app.create_app(author.clone()).unwrap();
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

        let mut a = service.create_app(author.clone()).unwrap();
        let a2 = service.create_app(author.clone()).unwrap();
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

        let mut a = service.create_app(author.clone()).unwrap();
        let mut a2 = service.create_app(author.clone()).unwrap();
        a.merge_both(&mut a2).unwrap();
        let res = service.verify_app(&a).unwrap();
        assert!(res);
        let res = service.verify_app(&a2).unwrap();
        assert!(res);
    }
}
