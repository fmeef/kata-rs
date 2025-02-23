use rusqlite::types::Value;
use scatterbrain::types::{Message, SbSession};

use crate::{
    api::proto::{ser::SubrosaMessage, ToUuid, APP_NAME},
    proto::post::AuthorOr,
};

use super::{
    connection::{Crud, OnConflict, SubrosaDb},
    entities::{CachedIdentity, NewsGroup, Posts, SubrosaDao},
};

pub fn conn_test(session: SbSession) {
    drop(session);
}

impl SubrosaDb {
    pub async fn sync(&self, sb_connection: &SbSession) -> anyhow::Result<()> {
        let sync_time = self.get_last_sync_date()?;

        let messages = sb_connection
            .get_messages_recieve_date(APP_NAME.to_owned(), None, sync_time, None)
            .await?;

        let unsent_posts = self.get_unsent_posts()?;
        let unsent_groups = self.get_unsent_groups()?;

        let sent_groups: Vec<Value> = unsent_groups.iter().map(|v| v.uuid.into()).collect();
        let sent_posts: Vec<Value> = unsent_posts.iter().map(|v| v.post_id.into()).collect();

        for post in unsent_groups {
            log::debug!("sending group {:?}", post.parent);
            let message = SubrosaMessage::Newsgroup(post.to_proto()).encode_to_vec()?;
            let message = Message::from_vec(message, APP_NAME.to_owned());
            sb_connection.send_messages(vec![message], None).await?;
        }

        for post in unsent_posts {
            log::debug!("sending posts {}", post.post_id);

            let post = post.to_proto(self)?;
            let author = post.author_or.map(|v| match v {
                AuthorOr::Author(v) => v.as_uuid(),
            });
            let message = SubrosaMessage::Post(post).encode_to_vec()?;
            let message = Message::from_vec(message, APP_NAME.to_owned());
            sb_connection.send_messages(vec![message], author).await?;
        }

        self.mark_sent_groups(sent_groups)?;
        self.mark_sent_posts(sent_posts)?;

        self.process_scatter_messages(&messages)?;
        Ok(())
    }

    pub fn insert_message(&self, message: &Message) -> anyhow::Result<()> {
        if let Err(err) = match SubrosaMessage::parse(&message.body) {
            Ok(SubrosaMessage::Post(post)) => {
                Posts::from_proto(post)?.insert_on_conflict(self, OnConflict::Ignore)
            }
            Ok(SubrosaMessage::Newsgroup(news)) => {
                NewsGroup::from_proto(news)?.insert_on_conflict(self, OnConflict::Ignore)
            }
            Ok(SubrosaMessage::User(id)) => {
                CachedIdentity::from_proto(id)?.insert_on_conflict(self, OnConflict::Ignore)
            }
            Ok(SubrosaMessage::MessageType(_)) => Ok(()),
            Err(err) => Err(err.into()),
        } {
            log::warn!("message parse failed {:?}", err);
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
