use std::io::Write;

use anyhow::anyhow;
use sequoia_openpgp::{
    parse::{stream::DetachedVerifierBuilder, Parse},
    serialize::stream::{Message, Signer},
};
use sequoia_wot::store::StoreError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    api::{
        pgp::{sign::PgpAppVerifier, UserHandle, POLICY},
        PgpApp,
    },
    error::InternalErr,
};

#[derive(Serialize, Deserialize, Clone)]
pub struct CircleAuthor {
    pub author: UserHandle,
    pub sig: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct Circle {
    pub author: Option<CircleAuthor>,
    pub members: Vec<UserHandle>,
    pub id: UserHandle,
}

impl Circle {
    fn bytes_buf(self) -> (Vec<u8>, Option<Vec<u8>>) {
        let mut size =
            self.id.as_bytes().len() + self.members.iter().map(|v| v.len()).sum::<usize>();
        if let Some(CircleAuthor { ref author, .. }) = self.author {
            size += author.as_bytes().len();
        }
        let mut out = Vec::with_capacity(size);
        if let Some(CircleAuthor { ref author, .. }) = self.author {
            out.extend_from_slice(author.as_bytes());
        }

        for member in self.members.iter() {
            out.extend_from_slice(member.as_bytes());
        }
        out.extend_from_slice(self.id.as_bytes());
        (out, self.author.map(|CircleAuthor { sig, .. }| sig))
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

            verifier.verify_bytes(&buf)?;
            return Ok(true);
        }

        Ok(false)
    }

    pub fn create_circle(&self, keys: Vec<UserHandle>) -> anyhow::Result<Circle> {
        let mut digest = Sha256::new();

        for member in &keys {
            digest.update(member.as_bytes());
        }

        let circle = Circle {
            members: keys,
            author: None,
            id: UserHandle::RawBytes(digest.finalize().to_vec()),
        };

        Ok(circle)
    }

    pub fn create_circle_signed(
        &self,
        author: UserHandle,
        keys: Vec<UserHandle>,
    ) -> anyhow::Result<Circle> {
        let cert = self.private_cert(&author)?;
        let mut out = Vec::new();
        {
            let private_kp = cert
                .keys()
                .secret()
                .with_policy(&POLICY, None)
                .supported()
                .alive()
                .revoked(false)
                .for_signing()
                .nth(0)
                .ok_or_else(|| InternalErr::NotFound("subkey"))?
                .key()
                .clone()
                .into_keypair()?;

            let message = Message::new(&mut out);

            let mut signer = Signer::new(message, private_kp)?.detached().build()?;

            let mut circle = self.create_circle(keys)?;

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
        pgp::{test_config, UserHandle},
        PgpApp, PgpAppTrait,
    };

    #[test]
    fn create_signed_circle() {
        let app = PgpApp::create(test_config("app")).unwrap();
        let keys = vec![UserHandle::from_hex("9FCF6558AC4927F1E7A43D80317375B449854036").unwrap()];

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
        let keys = vec![UserHandle::from_hex("9FCF6558AC4927F1E7A43D80317375B449854036").unwrap()];

        let key = app
            .generate_key("test@example.com".to_owned())
            .generate()
            .unwrap();

        let author = key.cert.fingerprint;

        let circle = app.create_circle_signed(author.clone(), keys).unwrap();
        let res = app.verify_circle(circle).unwrap();
        assert!(res);
    }
}
