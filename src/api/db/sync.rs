use prost::Message as Ser;
use scatterbrain::types::{Message, SbSession};

use crate::{
    api::proto::{ser::SubrosaMessage, ToUuid, APP_NAME},
    proto::post::AuthorOr,
};

use super::{
    connection::{Crud, SubrosaDb},
    entities::{CachedIdentity, NewsGroup, Posts, SubrosaDao},
};

pub fn conn_test(session: SbSession) {
    drop(session);
}

impl SubrosaDb {
    pub async fn sync(&self, sb_connection: SbSession) -> anyhow::Result<()> {
        let sync_time = self.get_last_sync_date()?;

        let messages = sb_connection
            .get_messages_recieve_date(APP_NAME.to_owned(), None, sync_time, None)
            .await?;

        let unsent_posts = self.get_unsent_posts()?;
        let unsent_groups = self.get_unsent_groups()?;

        for post in unsent_groups {
            let post = post.to_proto();
            let message = post.encode_to_vec();
            let message = Message::from_vec(message, APP_NAME.to_owned());
            sb_connection.send_messages(vec![message], None).await?;
        }

        for post in unsent_posts {
            let post = post.to_proto(self)?;
            let message = post.encode_to_vec();
            let message = Message::from_vec(message, APP_NAME.to_owned());
            sb_connection
                .send_messages(
                    vec![message],
                    post.author_or.map(|v| match v {
                        AuthorOr::Author(v) => v.as_uuid(),
                    }),
                )
                .await?;
        }

        self.process_scatter_messages(&messages)?;
        Ok(())
    }

    pub fn insert_message(&self, message: &Message) -> anyhow::Result<()> {
        match SubrosaMessage::parse(&message.body)? {
            SubrosaMessage::Post(post) => Posts::from_proto(post)?.insert(self)?,
            SubrosaMessage::Newsgroup(news) => NewsGroup::from_proto(news)?.insert(self)?,
            SubrosaMessage::User(id) => CachedIdentity::from_proto(id)?.insert(self)?,
            SubrosaMessage::MessageType(_) => (),
        }
        Ok(())
    }

    pub fn process_scatter_messages(&self, messages: &[Message]) -> anyhow::Result<()> {
        for message in messages {
            self.insert_message(message)?;
        }

        Ok(())
    }
}
