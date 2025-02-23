use scatterbrain::types::{Message, SbSession};

use super::{
    db::{
        connection::SubrosaDb,
        entities::{NewsGroup, Posts},
    },
    proto::{ser::SubrosaMessage, APP_NAME},
};

pub use anyhow::Result;

#[allow(async_fn_in_trait)]
pub trait Sender: Send + Sync {
    async fn send_post(&self, post: Posts, db: &SubrosaDb) -> Result<()>;
    async fn send_newsgroup(&self, newsgroup: NewsGroup) -> Result<()>;
}

impl Sender for SbSession {
    async fn send_post(&self, post: Posts, db: &SubrosaDb) -> Result<()> {
        let id = post.identity;

        let post = post.to_proto(db)?;
        let v = SubrosaMessage::Post(post).encode_to_vec()?;
        let message = Message::from_vec(v, APP_NAME.to_owned());
        self.send_messages(vec![message], id).await?;
        Ok(())
    }

    async fn send_newsgroup(&self, newsgroup: NewsGroup) -> Result<()> {
        let v = SubrosaMessage::Newsgroup(newsgroup.to_proto()).encode_to_vec()?;
        let message = Message::from_vec(v, APP_NAME.to_owned());

        self.send_messages(vec![message], None).await?;
        Ok(())
    }
}

#[cfg(test)]
mod test {

    #[test]
    fn write() {}
}
