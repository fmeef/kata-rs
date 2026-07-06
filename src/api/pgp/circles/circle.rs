use crate::{
    api::{
        db::{
            connection::{Crud, OnConflict},
            store::{CircleData, CircleMembersData, CircleWithMembers},
        },
        pgp::circles::CircleType,
        SqliteDb,
    },
    error::Result,
};
use anyhow::anyhow;
use flutter_rust_bridge::frb;
use sequoia_openpgp::{
    parse::{stream::DetachedVerifierBuilder, Parse},
    serialize::stream::{Message, Signer},
};
use sequoia_wot::store::StoreError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
};

use crate::{
    api::{
        pgp::{
            circles::{CircleEntry, CircleLike, CircleOr},
            sign::PgpAppVerifier,
            UserHandle, POLICY,
        },
        PgpApp,
    },
    error::InternalErr,
    frb_generated::StreamSink,
};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, PartialOrd, Eq, Ord)]
pub struct CircleAuthor {
    pub author: UserHandle,
    pub sig: Vec<u8>,
}

// #[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord)]
// #[frb(non_opaque)]
// pub struct NonOpaqueCircle {
//     pub id: UserHandle,
//     pub members: Vec<CircleEntry>,
//     pub author: Option<UserHandle>,
//     pub sig: Option<Vec<u8>>,
// }

// impl NonOpaqueCircle {
//     #[frb(sync)]
//     pub fn from_db(items: Vec<CircleWithMembers>) -> anyhow::Result<Vec<NonOpaqueCircle>> {
//         let circles = CircleOr::from_db(items)?;
//         // let out = circles.into_iter().map(|v| )
//         todo!()
//     }

//     // #[frb(sync)]
//     // pub fn from_circle_or(circle_or: CircleOr) -> anyhow::Result<NonOpaqueCircle> {
//     //     match circle_or {
//     //         CircleOr::Circle(circle) => Ok(circle.consume_members()),
//     //         CircleOr::App(app) =>
//     //     }
//     // }

//     pub fn to_db(&self, db: &SqliteDb) -> anyhow::Result<()> {
//         let entity = CircleData {
//             id: self.id.name(),
//             circle_type: "circle".to_owned(),
//             author: self.author.as_ref().map(|v| v.name()),
//             sig: self.sig.clone(),
//         };

//         entity.insert_on_conflict(db, OnConflict::Update)?;

//         for m in self.members.iter() {
//             if let Some(ref content) = m.content {
//                 content.to_db(db)?;
//             }

//             let entity = CircleMembersData {
//                 circle_member_id: None,
//                 member_id: m.id.name(),
//                 parent_id: self.id.name(),
//                 deleted: Some(false),
//                 tag: None,
//             };

//             entity.insert_on_conflict(db, OnConflict::Update)?;
//         }
//         Ok(())
//     }
// }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord)]
#[frb(opaque)]
pub(crate) struct CircleInner {
    pub(crate) author: Option<CircleAuthor>,
    pub(crate) members: BTreeMap<Vec<u8>, CircleOr>,
    pub(crate) id: UserHandle,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[frb(opaque)]
pub struct Circle {
    #[serde(flatten)]
    pub(crate) inner: CircleInner,
    #[serde(deserialize_with = "none", skip)]
    app: Option<PgpApp>,
}

impl PartialEq for Circle {
    fn eq(&self, other: &Self) -> bool {
        self.inner.eq(&other.inner)
    }
}

impl PartialOrd for Circle {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.inner.partial_cmp(&other.inner)
    }
}

impl Eq for Circle {}

impl Ord for Circle {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.inner.cmp(&other.inner)
    }
}

impl CircleLike for Circle {
    #[frb(sync)]
    fn get_id(&self) -> Vec<u8> {
        self.inner.id.as_bytes().to_owned()
    }

    #[frb(sync)]
    fn get_id_userhandle(&self) -> UserHandle {
        self.inner.id.clone()
    }

    fn iter_members(&self, sink: StreamSink<CircleEntry>) {
        for member in self.inner.members.values() {
            sink.add(CircleEntry::from_circle_or(member.clone()))
                .unwrap();
        }
    }
    #[frb(sync)]
    fn get_member(&self, id: UserHandle) -> Option<CircleEntry> {
        self.inner
            .members
            .get(id.as_bytes())
            .map(|v| CircleEntry::from_circle_or(v.clone()))
    }

    fn verify(&self) -> anyhow::Result<bool> {
        let res = self
            .app
            .as_ref()
            .ok_or(InternalErr::MissingPgpApp)?
            .verify_circle(self)
            .is_ok();
        Ok(res)
    }

    #[frb(sync)]
    fn get_type(&self) -> super::CircleType {
        CircleType::User
    }

    fn insert(&self, db: &SqliteDb) -> anyhow::Result<()> {
        self.to_db(db)
    }

    #[frb(sync)]
    fn get_members(&self) -> Vec<CircleEntry> {
        self.inner
            .members
            .values()
            .map(|v| CircleEntry::from_circle_or(v.clone()))
            .collect()
    }
}

impl Circle {
    pub fn is_member(&self, user: &UserHandle) -> bool {
        self.inner.members.contains_key(user.as_bytes())
    }

    // #[frb(sync)]
    // pub fn get_members(&self) -> NonOpaqueCircle {
    //     match self.inner.author {
    //         Some(ref author) => NonOpaqueCircle {
    //             members: self
    //                 .inner
    //                 .members
    //                 .iter()
    //                 .map(|(_, v)| CircleEntry::from_circle_or(v.clone()))
    //                 .collect(),
    //             id: self.inner.id.clone(),
    //             author: Some(author.author.clone()),
    //             sig: Some(author.sig.clone()),
    //         },
    //         None => NonOpaqueCircle {
    //             members: self
    //                 .inner
    //                 .members
    //                 .iter()
    //                 .map(|(_, v)| CircleEntry::from_circle_or(v.clone()))
    //                 .collect(),
    //             id: self.inner.id.clone(),
    //             author: None,
    //             sig: None,
    //         },
    //     }
    // }

    // #[frb(sync)]
    // pub fn consume_member(&self) -> NonOpaqueCircle {
    //     match self.inner.author {
    //         Some(author) => NonOpaqueCircle {
    //             members: self
    //                 .inner
    //                 .members
    //                 .into_iter()
    //                 .map(|(_, v)| CircleEntry::from_circle_or(v))
    //                 .collect(),
    //             id: self.inner.id,
    //             author: Some(author.author),
    //             sig: Some(author.sig),
    //         },
    //         None => NonOpaqueCircle {
    //             members: self
    //                 .inner
    //                 .members
    //                 .into_iter()
    //                 .map(|(_, v)| CircleEntry::from_circle_or(v))
    //                 .collect(),
    //             id: self.inner.id,
    //             author: None,
    //             sig: None,
    //         },
    //     }
    // }
}

impl CircleOr {
    #[frb(sync)]
    pub fn from_cert(user_handle: UserHandle) -> CircleOr {
        CircleOr::User(user_handle)
    }

    pub fn is_member(&self, user: &UserHandle) -> bool {
        match self {
            Self::Circle(c) => c.is_member(user),
            Self::User(u) => u == user,
            Self::App(u) => u.is_member(user),
        }
    }
}

impl Circle {
    pub fn to_db(&self, db: &SqliteDb) -> anyhow::Result<()> {
        let entity = CircleData {
            id: self.inner.id.name(),
            circle_type: "circle".to_owned(),
            author: self.inner.author.as_ref().map(|v| v.author.name()),
            sig: self.inner.author.as_ref().map(|v| v.sig.clone()),
        };

        entity.insert_on_conflict(db, OnConflict::Update)?;

        for m in self.inner.members.values() {
            m.to_db(db)?;
            let entity = CircleMembersData {
                circle_member_id: None,
                member_id: m.id_hex(),
                parent_id: self.inner.id.name(),
                deleted: Some(false),
                tag: None,
            };

            entity.insert_on_conflict(db, OnConflict::Update)?;
        }

        Ok(())
    }

    pub(crate) fn update_digest(&mut self) {
        let mut digest = Sha256::new();

        for member in self.inner.members.values() {
            digest.update(member.as_bytes());
        }

        self.inner.id = UserHandle::RawBytes(digest.finalize().to_vec());
    }

    pub(crate) fn new_mut(author: Option<UserHandle>, sig: Option<Vec<u8>>) -> Result<Self> {
        let author = match (author, sig) {
            (Some(author), Some(sig)) => Some(CircleAuthor { sig, author }),
            _ => None,
        };
        let res = Self {
            inner: CircleInner {
                author,
                members: BTreeMap::new(),
                id: UserHandle::RawBytes(Vec::new()),
            },
            app: None,
        };
        Ok(res)
    }

    fn members_reader<'a>(&'a self) -> Box<dyn std::io::Read + Send + Sync + 'a> {
        let v: &[u8] = &[];
        for (i, (_, member)) in self.inner.members.iter().enumerate() {
            let v = v.chain(member.as_bytes());
            if i + 1 == self.inner.members.len() {
                return Box::new(v);
            }
        }
        Box::new(v)
    }

    pub fn set_pgp(&mut self, pgp: PgpApp) {
        self.app = Some(pgp);
    }

    fn bytes_buf<'a>(&'a self) -> (impl std::io::Read + Send + Sync + 'a, Option<&'a [u8]>) {
        // let mut size = self.inner.id.as_bytes().len()
        //     + self
        //         .members
        //         .iter()
        //         .map(|v| v.as_bytes().len())
        //         .sum::<usize>();
        // if let Some(CircleAuthor { ref author, .. }) = self.inner.author {
        //     size += author.as_bytes().len();
        // }
        // let mut out = Vec::with_capacity(size);
        // if let Some(CircleAuthor { ref author, .. }) = self.inner.author {
        //     out.extend_from_slice(author.as_bytes());
        // }

        // for member in self.inner.members.iter() {
        //     out.extend_from_slice(member.as_bytes());
        // }
        // out.extend_from_slice(self.inner.id.as_bytes());
        //
        //

        let v = self.inner.id.as_bytes().chain(self.members_reader());

        let author = if let Some(ref author) = self.inner.author {
            author.author.as_bytes()
        } else {
            &[]
        };

        (
            v.chain(author),
            self.inner
                .author
                .as_ref()
                .map(|CircleAuthor { ref sig, .. }| sig.as_slice()),
        )
    }
}

impl PgpApp {
    pub fn verify_circle(&self, circle: &Circle) -> anyhow::Result<bool> {
        let mut helper = PgpAppVerifier::from_app(self);
        let (buf, sig) = circle.bytes_buf();
        if let Some(sig) = sig {
            let mut verifier = match DetachedVerifierBuilder::from_bytes(&sig)?
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

            verifier.verify_reader(buf)?;
            return Ok(true);
        }

        Ok(false)
    }

    pub fn create_circle(&self, keys: Vec<CircleOr>) -> anyhow::Result<Circle> {
        let mut digest = Sha256::new();

        for member in &keys {
            digest.update(member.as_bytes());
        }

        let inner = CircleInner {
            members: keys
                .into_iter()
                .map(|v| (v.as_bytes().to_owned(), v))
                .collect(),
            author: None,
            id: UserHandle::RawBytes(digest.finalize().to_vec()),
        };

        Ok(Circle {
            inner,
            app: Some(self.clone()),
        })
    }

    pub fn create_circle_signed(
        &self,
        author: UserHandle,
        keys: Vec<CircleOr>,
    ) -> anyhow::Result<Circle> {
        let mut out = Vec::new();
        {
            let private_kp = self.configured_privkey(&author, |p| p.for_signing())?;

            let message = Message::new(&mut out);

            let mut signer = Signer::new(message, private_kp)?.detached().build()?;

            let mut circle = self.create_circle(keys)?;

            signer.write_all(author.as_bytes())?;

            for member in circle.inner.members.values() {
                signer.write_all(member.as_bytes())?;
            }

            signer.write_all(circle.inner.id.as_bytes())?;
            signer.finalize()?;

            circle.inner.author = Some(CircleAuthor { author, sig: out });

            Ok(circle)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::api::{
        pgp::{circles::circle::CircleOr, test_config, UserHandle},
        PgpApp, PgpAppTrait,
    };

    #[test]
    fn create_signed_circle() {
        let app = PgpApp::create(test_config("app")).unwrap();
        let keys = vec![CircleOr::User(
            UserHandle::from_hex("9FCF6558AC4927F1E7A43D80317375B449854036").unwrap(),
        )];

        let key = app
            .generate_key("test@example.com".to_owned())
            .generate()
            .unwrap();

        let author = key.cert.fingerprint;

        let circle = app.create_circle_signed(author.clone(), keys).unwrap();
        assert_eq!(author.name(), circle.inner.author.unwrap().author.name())
    }

    #[test]
    fn verify_signed_circle() {
        let app = PgpApp::create(test_config("app")).unwrap();
        let keys = vec![CircleOr::User(
            UserHandle::from_hex("9FCF6558AC4927F1E7A43D80317375B449854036").unwrap(),
        )];
        let key = app
            .generate_key("test@example.com".to_owned())
            .generate()
            .unwrap();

        let author = key.cert.fingerprint;

        let circle = app.create_circle_signed(author.clone(), keys).unwrap();
        let res = app.verify_circle(&circle).unwrap();
        assert!(res);
    }

    #[test]
    fn verify_membership() {
        let app = PgpApp::create(test_config("app")).unwrap();
        let keys = vec![CircleOr::User(
            UserHandle::from_hex("9FCF6558AC4927F1E7A43D80317375B449854036").unwrap(),
        )];

        let circle = app.create_circle(keys).unwrap();

        let key = UserHandle::from_hex("9FCF6558AC4927F1E7A43D80317375B449854036").unwrap();

        let member = circle.is_member(&key);

        assert!(member)
    }
}
