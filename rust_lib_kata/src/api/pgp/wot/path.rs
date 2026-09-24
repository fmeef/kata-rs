use std::collections::{HashMap, HashSet};

use serde::Serialize;

#[derive(Serialize, PartialEq, Eq, Hash)]
pub struct GraphEdge {
    #[serde(rename = "srcdId")]
    pub src_id: String,
    #[serde(rename = "dstId")]
    pub dst_id: String,
    pub ranking: i64,
    #[serde(rename = "edgeName")]
    pub edge_name: String,
}

#[derive(Serialize, PartialEq, Eq, Hash)]
pub struct GraphVertex {
    pub id: String,
    pub tag: String,
    pub tags: Vec<String>,
    pub data: Option<Vec<u8>>,
}

pub struct WotGraph {
    pub edges: HashSet<GraphEdge>,
    pub vertices: HashMap<String, GraphVertex>,
    pub trust: usize,
}

impl WotGraph {
    pub(crate) fn new(trust: usize) -> Self {
        WotGraph {
            edges: HashSet::new(),
            vertices: HashMap::new(),
            trust,
        }
    }
}
