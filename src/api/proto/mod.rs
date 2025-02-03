use crate::proto::ProtoUuid;

pub(crate) const APP_NAME: &str = "newsnet";

pub mod ser;
pub mod types;

pub trait ToUuid {
    fn as_uuid(&self) -> uuid::Uuid;
    fn as_proto(&self) -> ProtoUuid;
}

impl ToUuid for ProtoUuid {
    fn as_uuid(&self) -> uuid::Uuid {
        uuid::Uuid::from_u64_pair(self.upper, self.lower)
    }

    fn as_proto(&self) -> ProtoUuid {
        *self
    }
}

impl ToUuid for uuid::Uuid {
    fn as_uuid(&self) -> uuid::Uuid {
        *self
    }

    fn as_proto(&self) -> ProtoUuid {
        let (upper, lower) = self.as_u64_pair();
        ProtoUuid { upper, lower }
    }
}
