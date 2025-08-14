use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex, MutexGuard, RwLock},
};

use flutter_rust_bridge::{frb, BaseAsyncRuntime, DartFnFuture};
use rusqlite::Connection;

use crate::frb_generated::FLUTTER_RUST_BRIDGE_HANDLER;

use super::entities::NewsGroup;

#[derive(Copy, Clone)]
pub enum OnConflict {
    Update,
    Ignore,
    Abort,
}

pub trait Crud {
    fn insert(&self, conn: &SqliteDb) -> anyhow::Result<()>;
    fn update(&self, conn: &SqliteDb) -> anyhow::Result<()>;
    fn delete(self, conn: &SqliteDb) -> anyhow::Result<()>;
    fn insert_on_conflict(&self, conn: &SqliteDb, on_conflict: OnConflict) -> anyhow::Result<()>;
}

type WatcherCbs =
    Arc<RwLock<HashMap<String, Box<dyn Fn(SqliteDb) -> DartFnFuture<()> + Send + Sync>>>>;

struct WatcherInner {
    parent: SqliteDb,
    idx: u32,
    cbs: WatcherCbs,
}

pub struct Watcher(Arc<WatcherInner>);

impl Clone for Watcher {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl Watcher {
    fn new(parent: SqliteDb, idx: u32) -> Self {
        Self(Arc::new(WatcherInner {
            parent,
            cbs: Arc::new(RwLock::new(HashMap::new())),
            idx,
        }))
    }
    pub fn watch(
        &self,
        table: String,
        cb: impl Fn(SqliteDb) -> DartFnFuture<()> + Send + Sync + 'static,
    ) {
        FLUTTER_RUST_BRIDGE_HANDLER
            .async_runtime()
            .spawn(cb(self.0.parent.clone()));
        self.0.cbs.write().unwrap().insert(table, Box::new(cb));
    }
}

impl Drop for WatcherInner {
    fn drop(&mut self) {
        self.parent.0.watchers.write().unwrap().remove(&self.idx);
    }
}

pub(crate) struct SqliteDbInner {
    pub(crate) conn: Mutex<Connection>,
    pub(crate) watchers: RwLock<BTreeMap<u32, WatcherCbs>>,
    watcher_idx: RwLock<u32>,
}

pub struct SqliteDb(pub(crate) Arc<SqliteDbInner>);

impl Clone for SqliteDb {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

pub trait Dao {
    fn get_connection(&self) -> &'_ SqliteDb;
}

impl Dao for SqliteDb {
    fn get_connection(&self) -> &'_ SqliteDb {
        self
    }
}
pub(crate) type DbConnection<'a> = MutexGuard<'a, Connection>;

impl SqliteDb {
    #[cfg(test)]
    pub(crate) fn from_conn(conn: Connection) -> SqliteDb {
        SqliteDb(Arc::new(SqliteDbInner {
            conn: Mutex::new(conn),
            watchers: RwLock::new(BTreeMap::new()),
            watcher_idx: RwLock::new(0),
        }))
    }

    #[frb(sync)]
    pub fn get_watcher(&self) -> Watcher {
        let mut wl = self.0.watchers.write().unwrap();
        let mut idx = self.0.watcher_idx.write().unwrap();
        *idx = idx.wrapping_add(1);
        let w = Watcher::new(self.clone(), *idx);
        wl.insert(*idx, Arc::clone(&w.0.cbs));

        let s = self.clone();
        let c = self.0.conn.lock().unwrap();
        c.update_hook(Some(move |_, _: &str, tablename: &str, _| {
            for watcher in s.0.watchers.read().unwrap().values() {
                for (tb, cb) in watcher.read().unwrap().iter() {
                    if tb != tablename {
                        continue;
                    }
                    FLUTTER_RUST_BRIDGE_HANDLER
                        .async_runtime()
                        .spawn(cb(s.clone()));
                }
            }
        }));
        w
    }

    #[frb(sync)]
    pub fn new(path: &str) -> anyhow::Result<SqliteDb> {
        let conn = Connection::open(path)?;
        rusqlite::vtab::array::load_module(&conn)?;
        Ok(SqliteDb(Arc::new(SqliteDbInner {
            conn: Mutex::new(conn),
            watchers: RwLock::new(BTreeMap::new()),
            watcher_idx: RwLock::new(0),
        })))
    }

    #[frb(sync)]
    pub fn new_in_memory() -> anyhow::Result<SqliteDb> {
        let conn = Connection::open_in_memory()?;
        rusqlite::vtab::array::load_module(&conn)?;
        Ok(SqliteDb(Arc::new(SqliteDbInner {
            conn: Mutex::new(conn),
            watchers: RwLock::new(BTreeMap::new()),
            watcher_idx: RwLock::new(0),
        })))
    }

    pub fn insert_group(&self, group: &NewsGroup) -> anyhow::Result<()> {
        group.insert(self)?;
        Ok(())
    }

    pub(crate) fn connection<'a>(&'a self) -> DbConnection<'a> {
        self.0.conn.lock().unwrap()
    }
}
