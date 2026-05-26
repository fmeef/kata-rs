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
    collections::BTreeSet,
    io::{Read, Write},
};

use crate::api::{
    pgp::{sign::PgpAppVerifier, UserHandle, POLICY},
    PgpApp,
};

#[derive(Serialize, Deserialize, Clone, PartialEq, PartialOrd, Eq, Ord)]
pub struct CircleAuthor {
    pub author: UserHandle,
    pub sig: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, PartialOrd, Eq, Ord)]
#[frb(non_opaque)]
pub enum CircleOr {
    Circle(Circle),
    User(UserHandle),
}

impl CircleOr {
    fn as_bytes(&self) -> &'_ [u8] {
        match self {
            Self::Circle(Circle { id, .. }) => id.as_bytes(),
            Self::User(user) => user.as_bytes(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, PartialOrd, Eq, Ord)]
#[frb(opaque)]
pub struct Circle {
    author: Option<CircleAuthor>,
    members: BTreeSet<CircleOr>,
    id: UserHandle,
}

impl Circle {
    pub fn is_member(&self, user: &UserHandle) -> bool {
        self.members.iter().any(|v| v.is_member(user))
    }

    pub fn create(keys: Vec<CircleOr>) -> anyhow::Result<Circle> {
        let mut digest = Sha256::new();

        for member in &keys {
            digest.update(member.as_bytes());
        }

        let circle = Circle {
            members: keys.into_iter().collect(),
            author: None,
            id: UserHandle::RawBytes(digest.finalize().to_vec()),
        };

        Ok(circle)
    }
}

impl CircleOr {
    pub fn is_member(&self, user: &UserHandle) -> bool {
        match self {
            Self::Circle(c) => c.is_member(user),
            Self::User(u) => u == user,
        }
    }
}

impl Circle {
    fn members_reader<'a>(&'a self) -> Box<dyn std::io::Read + Send + Sync + 'a> {
        let v: &[u8] = &[];
        for (i, member) in self.members.iter().enumerate() {
            let v = v.chain(member.as_bytes());
            if i + 1 == self.members.len() {
                return Box::new(v);
            }
        }
        Box::new(v)
    }

    fn bytes_buf<'a>(&'a self) -> (impl std::io::Read + Send + Sync + 'a, Option<&'a [u8]>) {
        // let mut size = self.id.as_bytes().len()
        //     + self
        //         .members
        //         .iter()
        //         .map(|v| v.as_bytes().len())
        //         .sum::<usize>();
        // if let Some(CircleAuthor { ref author, .. }) = self.author {
        //     size += author.as_bytes().len();
        // }
        // let mut out = Vec::with_capacity(size);
        // if let Some(CircleAuthor { ref author, .. }) = self.author {
        //     out.extend_from_slice(author.as_bytes());
        // }

        // for member in self.members.iter() {
        //     out.extend_from_slice(member.as_bytes());
        // }
        // out.extend_from_slice(self.id.as_bytes());
        //
        //

        let v = self.id.as_bytes().chain(self.members_reader());

        let author = if let Some(ref author) = self.author {
            author.author.as_bytes()
        } else {
            &[]
        };

        (
            v.chain(author),
            self.author
                .as_ref()
                .map(|CircleAuthor { ref sig, .. }| sig.as_slice()),
        )
    }
}

impl PgpApp {
    pub fn verify_circle(&self, circle: Circle) -> anyhow::Result<bool> {
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

            let mut circle = Circle::create(keys)?;

            signer.write_all(author.as_bytes())?;

            for member in circle.members.iter() {
                signer.write_all(member.as_bytes())?;
            }

            signer.write_all(circle.id.as_bytes())?;
            signer.finalize()?;

            circle.author = Some(CircleAuthor { author, sig: out });

            Ok(circle)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::api::{
        pgp::{
            circles::circle::{Circle, CircleOr},
            test_config, UserHandle,
        },
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
        assert_eq!(author.name(), circle.author.unwrap().author.name())
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
        let res = app.verify_circle(circle).unwrap();
        assert!(res);
    }

    #[test]
    fn verify_membership() {
        let app = PgpApp::create(test_config("app")).unwrap();
        let keys = vec![CircleOr::User(
            UserHandle::from_hex("9FCF6558AC4927F1E7A43D80317375B449854036").unwrap(),
        )];

        let circle = Circle::create(keys).unwrap();

        let key = UserHandle::from_hex("9FCF6558AC4927F1E7A43D80317375B449854036").unwrap();

        let member = circle.is_member(&key);

        assert!(member)
    }
}
