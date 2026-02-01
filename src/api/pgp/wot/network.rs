use std::collections::BTreeMap;

use flutter_rust_bridge::frb;
use sequoia_cert_store::store::Pep;
use sequoia_cert_store::Store as CertStore;
use sequoia_openpgp::Fingerprint;
use sequoia_wot::store::Store;
use sequoia_wot::{Network, Roots};

use crate::api::pgp::{
    mut_store::MutStore,
    wot::path::{GraphEdge, GraphVertex, WotGraph},
};
use crate::error::InternalErr;

impl CertNetwork<'static, Pep> {
    pub fn from_store<R>(store: MutStore<'static, Pep>, roots: R) -> anyhow::Result<StoreNetwork>
    where
        R: Into<Roots>,
    {
        Ok(StoreNetwork(CertNetwork(Network::new(store, roots)?)))
    }

    pub fn from_store_unrooted(store: MutStore<'static, Pep>) -> anyhow::Result<StoreNetwork> {
        Ok(StoreNetwork(CertNetwork(Network::new(
            store,
            Roots::empty(),
        )?)))
    }
}

pub trait CertNetworkTrait {
    fn authenticate(&self, remote: &str, trust: usize) -> anyhow::Result<WotGraph>;

    fn dump_all(&self) -> anyhow::Result<WotGraph>;
}

pub(crate) struct CertNetwork<'a, T>(Network<MutStore<'a, T>>)
where
    T: sequoia_cert_store::Store<'a> + Sync + Send + sequoia_wot::sequoia_cert_store::Store<'a>;

#[frb(opaque)]
pub struct SharedNetwork(CertNetwork<'static, MutStore<'static, Pep>>);

#[frb(opaque)]
pub struct StoreNetwork(CertNetwork<'static, Pep>);

impl CertNetworkTrait for SharedNetwork {
    fn authenticate(&self, remote: &str, trust: usize) -> anyhow::Result<WotGraph> {
        self.0.authenticate_internal(remote, trust)
    }

    fn dump_all(&self) -> anyhow::Result<WotGraph> {
        self.0.dump_internal()
    }
}

impl CertNetworkTrait for StoreNetwork {
    fn authenticate(&self, remote: &str, trust: usize) -> anyhow::Result<WotGraph> {
        self.0.authenticate_internal(remote, trust)
    }

    fn dump_all(&self) -> anyhow::Result<WotGraph> {
        self.0.dump_internal()
    }
}

impl<'a, T> CertNetwork<'a, T>
where
    T: sequoia_cert_store::Store<'a> + Sync + Send,
{
    fn dump_internal(&self) -> anyhow::Result<WotGraph> {
        let mut out = WotGraph::new(0);
        let mut vertexes = BTreeMap::<Fingerprint, GraphVertex>::new();
        let mut edges = BTreeMap::<(Fingerprint, Fingerprint), GraphEdge>::new();
        for fingerprint in self.0.iter_fingerprints() {
            let certs = match self
                .0
                .certifications_of(&fingerprint, sequoia_wot::Depth::Unconstrained)
            {
                Ok(cert) => cert,
                Err(err) => {
                    log::error!("failed to get cert: {err}");
                    continue;
                }
            };

            for cert in certs.iter() {
                for cert in [cert.issuer(), cert.target()] {
                    vertexes
                        .entry(cert.fingerprint())
                        .or_insert_with(|| GraphVertex {
                            id: cert
                                .primary_userid()
                                .map(|v| v.userid().to_string())
                                .unwrap_or_else(|| cert.fingerprint().to_hex()),
                            tag: cert.fingerprint().to_hex(),
                            tags: cert.userids().map(|v| v.userid().to_string()).collect(),
                            data: None,
                        });
                }

                edges
                    .entry((cert.issuer().fingerprint(), cert.target().fingerprint()))
                    .or_insert_with(|| GraphEdge {
                        src_id: cert
                            .issuer()
                            .primary_userid()
                            .map(|v| v.userid().to_string())
                            .unwrap_or_else(|| cert.issuer().fingerprint().to_hex()),
                        dst_id: cert
                            .target()
                            .primary_userid()
                            .map(|v| v.userid().to_string())
                            .unwrap_or_else(|| cert.target().fingerprint().to_hex()),
                        ranking: 0,
                        edge_name: "".to_owned(),
                    });
            }
        }

        out.vertices = vertexes.into_values().map(|v| (v.id.clone(), v)).collect();
        out.edges = edges.into_values().collect();

        Ok(out)
    }

    fn authenticate_internal(&self, remote: &str, trust: usize) -> anyhow::Result<WotGraph> {
        let cert = self.0.lookup_by_cert_fpr(&Fingerprint::from_hex(remote)?)?;

        let userid = cert
            .userids()
            .next()
            .ok_or_else(|| InternalErr::Generic("userid not found"))?;
        let fingerprint = cert.fingerprint();

        let paths = self.0.authenticate(userid, &fingerprint, trust);

        let mut out = WotGraph::new(paths.amount());
        let mut vertexes = BTreeMap::<Fingerprint, GraphVertex>::new();
        let mut edges = BTreeMap::<(Fingerprint, Fingerprint), GraphEdge>::new();
        let mut prev: Option<sequoia_wot::CertSynopsis> = None;
        for (path, weight) in paths.into_iter() {
            for cert in path.certificates() {
                vertexes
                    .entry(cert.fingerprint())
                    .or_insert_with(|| GraphVertex {
                        id: cert
                            .primary_userid()
                            .map(|v| v.userid().to_string())
                            .unwrap_or_else(|| cert.fingerprint().to_hex()),
                        tag: cert.fingerprint().to_hex(),
                        tags: Vec::new(),
                        data: None,
                    });

                if let Some(prev) = prev.take() {
                    edges
                        .entry((prev.fingerprint(), cert.fingerprint()))
                        .or_insert_with(|| GraphEdge {
                            src_id: prev
                                .primary_userid()
                                .map(|v| v.userid().to_string())
                                .unwrap_or_else(|| cert.fingerprint().to_hex()),
                            dst_id: cert
                                .primary_userid()
                                .map(|v| v.userid().to_string())
                                .unwrap_or_else(|| cert.fingerprint().to_hex()),
                            ranking: weight as i64,
                            edge_name: "".to_owned(),
                        });
                }

                prev = Some(cert.clone());
            }
        }
        out.vertices = vertexes.into_values().map(|v| (v.id.clone(), v)).collect();
        out.edges = edges.into_values().collect();
        Ok(out)
    }
}

#[cfg(test)]
mod test {
    use crate::api::{
        pgp::{sign::TrustLevel, test_config, wot::network::CertNetworkTrait},
        PgpApp, PgpAppTrait,
    };

    #[test]
    fn verify_wot() {
        let app = PgpApp::create(test_config("app")).unwrap();

        let key1 = app
            .generate_key("test1@example.com".to_owned())
            .generate()
            .unwrap();

        let key2 = app
            .generate_key("test2@example.com".to_owned())
            .generate()
            .unwrap();

        assert!(key2.has_private());

        app.sign_with_trust_level(
            &key1.cert.fingerprint.name(),
            &key2.cert.fingerprint.name(),
            1,
            TrustLevel::Partial,
        )
        .unwrap();

        let network = app
            .network_from_fingerprints(vec![
                key1.cert.fingerprint.name(),
                key2.cert.fingerprint.name(),
            ])
            .unwrap();

        let path = network
            .authenticate(&key2.cert.fingerprint.name(), 120)
            .unwrap();

        assert_ne!(path.trust, 0);
    }

    #[test]
    fn verify_wot_single_root() {
        let app = PgpApp::create(test_config("app")).unwrap();

        let key1 = app
            .generate_key("test1@example.com".to_owned())
            .generate()
            .unwrap();

        let key2 = app
            .generate_key("test2@example.com".to_owned())
            .generate()
            .unwrap();

        assert!(key2.has_private());

        app.sign_with_trust_level(
            &key1.cert.fingerprint.name(),
            &key2.cert.fingerprint.name(),
            120,
            TrustLevel::Partial,
        )
        .unwrap();

        let network = app
            .network_from_fingerprints(vec![key1.cert.fingerprint.name()])
            .unwrap();

        let path = network
            .authenticate(&key2.cert.fingerprint.name(), 120)
            .unwrap();

        assert_ne!(path.trust, 0);
    }
}
