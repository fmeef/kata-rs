use crate::error::Result;
use crate::proto;
pub use crate::scatterbrain::api::types::GetType;
pub use crate::scatterbrain::serialize::ProtoUuid;
use flutter_rust_bridge::frb;
use prost::{bytes::BufMut, Message as Ser};
pub use scatterbrain::response::Message;

use super::APP_NAME;

#[derive(Clone, Debug)]
pub enum SubrosaMessage {
    MessageType(proto::TypePrefix),
    Newsgroup(proto::NewsGroup),
    Post(proto::Post),
    User(proto::User),
}

fn parse_length_delimited<T>(message: &[u8]) -> Result<(T, &'_ [u8])>
where
    T: prost::Message + Default,
{
    if message.len() < 4 {
        return Err(crate::error::SubrosaErr::ParseError);
    }
    let len: i32 = i32::from_be_bytes(message[0..4].try_into().unwrap());

    if message.len() < 4 + len as usize {
        return Err(crate::error::SubrosaErr::ParseError);
    }

    let m = &message[4..4 + len as usize];
    Ok((Ser::decode(m)?, &message[4 + len as usize..]))
}

impl SubrosaMessage {
    #[frb(sync)]
    pub fn handle_subrosa_message(sb_message: &Message) -> anyhow::Result<SubrosaMessage> {
        Ok(SubrosaMessage::parse(&sb_message.body)?)
    }

    // pub fn insert(&self, db: &SubrosaDb) -> anyhow::Result<()> {
    //     match self {
    //         SubrosaMessage::Post(m) => ,
    //         SubrosaMessage::MessageType(m) => (),
    //         SubrosaMessage::User(m) => m.encoded_len(),
    //         SubrosaMessage::Newsgroup(m) => m.encoded_len(),
    //     }
    //     Ok(())
    // }

    pub async fn get_message(&self) -> anyhow::Result<Message> {
        let size = match self {
            SubrosaMessage::Post(m) => m.encoded_len(),
            SubrosaMessage::MessageType(m) => m.encoded_len(),
            SubrosaMessage::User(m) => m.encoded_len(),
            SubrosaMessage::Newsgroup(m) => m.encoded_len(),
        };
        let mut v = Vec::with_capacity(size);
        self.encode(&mut v)?;
        let m = Message::from_vec(v, APP_NAME.to_owned());
        Ok(m)
    }

    pub(crate) fn parse(message: &[u8]) -> Result<SubrosaMessage> {
        let (t, message): (proto::TypePrefix, _) = parse_length_delimited(message)?;
        let typelen = t.encoded_len();
        if message.len() < (4 + typelen) {
            return Err(crate::error::SubrosaErr::ParseError);
        }

        let r = match t.post_type() {
            proto::PostType::Type => {
                SubrosaMessage::MessageType(parse_length_delimited(message)?.0)
            }
            proto::PostType::Post => SubrosaMessage::Post(parse_length_delimited(message)?.0),
            proto::PostType::User => SubrosaMessage::User(parse_length_delimited(message)?.0),
            proto::PostType::Newsgroup => {
                SubrosaMessage::Newsgroup(parse_length_delimited(message)?.0)
            }
        };

        Ok(r)
    }

    pub(crate) fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        self.encode(&mut v)?;
        Ok(v)
    }

    fn encode<T>(&self, writer: &mut T) -> Result<()>
    where
        T: BufMut,
    {
        let (t, l) = match self {
            SubrosaMessage::MessageType(m) => (proto::PostType::Type, m.encoded_len()),
            SubrosaMessage::Newsgroup(m) => (proto::PostType::Newsgroup, m.encoded_len()),
            SubrosaMessage::Post(m) => (proto::PostType::Post, m.encoded_len()),
            SubrosaMessage::User(m) => (proto::PostType::User, m.encoded_len()),
        };

        println!("wrote size {}", l);

        let tp = proto::TypePrefix {
            post_type: t.into(),
        };
        writer.put_i32(tp.encoded_len() as i32);
        tp.encode(writer)?;

        if l > i32::MAX as usize {
            return Err(crate::error::SubrosaErr::ParseError);
        }

        writer.put_i32(l as i32);

        match self {
            SubrosaMessage::MessageType(m) => m.encode(writer)?,
            SubrosaMessage::Newsgroup(m) => m.encode(writer)?,
            SubrosaMessage::Post(m) => m.encode(writer)?,
            SubrosaMessage::User(m) => m.encode(writer)?,
        };

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use uuid::Uuid;

    use crate::{api::proto::ToUuid, proto};

    use super::SubrosaMessage;

    #[test]
    fn parse_encode() {
        let ng = SubrosaMessage::Newsgroup(proto::NewsGroup {
            name: "test group".to_owned(),
            parent_option: None,
            uuid: Some(Uuid::new_v4().as_proto()),
            description: "test description".to_owned(),
        });

        let mut out = vec![];

        ng.encode(&mut out).unwrap();

        let decode = SubrosaMessage::parse(&out).unwrap();
    }
}
