use std::collections::BTreeSet;

use flutter_rust_bridge::frb;
use sequoia_openpgp::serialize::stream::{Message, Signer};
use serde::{Deserialize, Serialize};

use crate::api::{
    pgp::{circles::circle::CircleOr, UserHandle},
    PgpApp,
};

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemberTag {
    Merge,
    Overwrite,
    Delete,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AppMember {
    pub member: CircleOr,
    pub tag: MemberTag,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[frb(opaque)]
pub struct CircleApp {
    author: UserHandle,
    children: BTreeSet<AppMember>,
    sig: Vec<u8>,
}

impl PgpApp {
    pub fn create_app(&self, owner: UserHandle) -> anyhow::Result<CircleApp> {
        let mut out = Vec::new();
        {
            let cert = self.configured_privkey(&owner, |v| v.for_signing())?;

            let message = Message::new(&mut out);

            let mut signer = Signer::new(message, cert)?.detached().build()?;
        }

        todo!()
    }
}
