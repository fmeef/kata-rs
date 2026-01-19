use anyhow::anyhow;
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use flutter_rust_bridge::frb;
use sequoia_cert_store::{LazyCert, Store, StoreUpdate};
use sequoia_openpgp::cert::amalgamation::ValidateAmalgamation;
use sequoia_openpgp::serialize::stream::Compressor;
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::types::{CompressionAlgorithm, SignatureType};
use sequoia_openpgp::{
    parse::stream::VerifierBuilder, serialize::stream::LiteralWriter, KeyHandle,
};
use sequoia_openpgp::{
    parse::Parse,
    serialize::stream::{Message, Signer},
};
use sequoia_openpgp::{Cert, Fingerprint, Packet};
use sequoia_wot::store::StoreError;
use serde::{Deserialize, Serialize};
use std::cell::LazyCell;
use std::io::Read;
use std::io::Write;
use std::sync::Arc;

use crate::api::pgp::cert::PgpCertWithIds;
use crate::api::pgp::{PgpServiceTrait, UserHandle};
use crate::{
    api::{
        pgp::{sign::PgpAppVerifier, POLICY},
        PgpApp,
    },
    error::InternalErr,
};

pub struct VerifyResult {
    pub fingerprints: Vec<String>,
    pub content: Option<QrCodeContent>,
    pub key: Option<PgpCertWithIds>,
    pub is_stub: bool,
}

#[derive(Serialize, Deserialize)]
pub struct QrCodeContent {
    #[serde(rename = "r")]
    pub resource: String,
    #[serde(rename = "h")]
    pub handle: Option<String>,
    #[serde(rename = "d")]
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[frb(unignore)]
pub struct QrCodeKey {
    #[serde(rename = "c")]
    pub content: Vec<u8>,
    #[serde(rename = "f")]
    pub fullkey: Option<Vec<u8>>,
}

fn strip_cert(cert: Cert) -> anyhow::Result<Cert> {
    let packets = cert.into_packets().filter_map(|p| match p {
        Packet::Signature(s) => match s.typ() {
            SignatureType::KeyRevocation => Some(Packet::Signature(s)),
            SignatureType::CertificationRevocation => Some(Packet::Signature(s)),
            SignatureType::DirectKey => Some(Packet::Signature(s)),
            _ => None,
        },
        Packet::Trust(_) => None,
        Packet::OnePassSig(_) => None,
        p => Some(p),
    });
    Ok(Cert::from_packets(packets)?)
}

impl PgpApp {
    pub fn is_stub(&self, fingerprint: &str) -> anyhow::Result<bool> {
        let cert = self
            .pgp
            .store
            .lookup_by_cert_fpr(&Fingerprint::from_hex(fingerprint)?)?;

        let strip = strip_cert(cert.to_cert()?.clone())?;
        Ok(strip == *cert.to_cert()?)
    }

    pub fn get_qr(
        &self,
        resource: String,
        handle: Option<String>,
        description: Option<String>,
        key: &UserHandle,
        full_key: bool,
    ) -> anyhow::Result<Vec<u8>> {
        let mut v = Vec::new();
        //let mut v = GzEncoder::new(Vec::new(), Compression::best());
        let cert = self.private_cert(key)?;
        let fullkey = if full_key {
            let export = cert.clone().strip_secret_key_material();
            let export = export.retain_subkeys(|p| {
                if let Ok(p) = p.with_policy(&POLICY, None) {
                    p.for_certification()
                } else {
                    false
                }
            });
            // let fp = KeyHandle::Fingerprint(export.fingerprint());
            let export = strip_cert(export)?;
            Some(export.to_vec()?)
        } else {
            None
        };
        {
            let message = Message::new(&mut v);

            let content = QrCodeContent {
                resource,
                handle,
                description,
            };

            let private_kp = cert
                .keys()
                .secret()
                .with_policy(&POLICY, None)
                .supported()
                .alive()
                .revoked(false)
                .for_certification()
                .nth(0)
                .ok_or_else(|| InternalErr::NotFound("subkey"))?
                .key()
                .clone()
                .into_keypair()?;

            let signer = Signer::new(message, private_kp)?.build()?;
            let signer = Compressor::new(signer)
                .algo(CompressionAlgorithm::BZip2)
                .build()?;
            let mut signer = LiteralWriter::new(signer).build()?;

            let text = rmp_serde::to_vec_named(&content)?;
            signer.write_all(&text)?;
            signer.finalize()?;
        }

        let out = QrCodeKey {
            content: v,
            fullkey,
        };

        Ok(rmp_serde::to_vec_named(&out)?)
    }

    pub fn verify_qr_all_certs(&self, content: &[u8]) -> anyhow::Result<VerifyResult> {
        let content: QrCodeKey = rmp_serde::from_slice(content)?;
        let key = if let Some(ref fullkey) = content.fullkey {
            let cert = Cert::from_bytes(fullkey)?;
            self.pgp
                .store
                .update(Arc::new(LazyCert::from_cert(cert.clone())))?;

            Some(
                self.pgp
                    .get_key_from_fingerprint(&UserHandle::KeyHandle(cert.key_handle()))?,
            )
        } else {
            None
        };

        let mut helper = PgpAppVerifier::from_app(self);

        let mut verifier = match VerifierBuilder::from_bytes(&content.content)?.with_policy(
            &POLICY,
            None,
            &mut helper,
        ) {
            Ok(v) => Ok(v),
            Err(e) => Err(match e.downcast() {
                Ok(StoreError::NotFound(kh)) => {
                    return Ok(VerifyResult {
                        fingerprints: match kh {
                            KeyHandle::Fingerprint(fp) => vec![fp.to_hex()],
                            KeyHandle::KeyID(id) => vec![id.to_hex()],
                        },
                        key,
                        content: None,
                        is_stub: true,
                    });
                }

                Err(e) => e,
                Ok(e) => anyhow!(e),
            }),
        }?;

        let mut out = Vec::new();

        verifier.read_to_end(&mut out)?;

        let is_stub = if let Some(ref key) = key {
            self.is_stub(&key.cert.fingerprint)?
        } else {
            true
        };

        Ok(VerifyResult {
            fingerprints: helper.fingerprints,
            content: Some(rmp_serde::from_slice(&out)?),
            key,
            is_stub,
        })
    }
}

impl QrCodeContent {
    // pub fn from_bytes(bytes: Vec<u8>) -> anyhow::Result<Self> {
    //     let mut decoder = GzDecoder::new(bytes.as_slice());
    //     let mut json = String::new();
    //     decoder.read_to_string(&mut json)?;
    //     Ok(serde_json::from_str(&json)?)
    // }

    // pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
    //     let json = serde_json::to_string(self)?;
    //     let mut encoder = GzEncoder::new(json.as_bytes(), Compression::default());
    //     let mut out = Vec::new();
    //     encoder.read_to_end(&mut out)?;
    //     Ok(out)
    // }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use sequoia_cert_store::{LazyCert, Store, StoreUpdate};
    use sequoia_openpgp::Fingerprint;

    use crate::api::{
        pgp::{test_config, UserHandle},
        ser::strip_cert,
        PgpApp, PgpAppTrait,
    };

    #[test]
    fn qr_code_signing() {
        for full in [false, true] {
            let app = PgpApp::create(test_config("app")).unwrap();

            let key = app
                .generate_key("test@example.com".to_owned())
                .generate()
                .unwrap();

            app.get_qr(
                "test@example.com".to_owned(),
                None,
                None,
                &UserHandle::from_hex(&key.cert.fingerprint).unwrap(),
                full,
            )
            .unwrap();
        }
    }

    #[test]
    fn qr_code_verify() {
        for full in [false, true] {
            let app = PgpApp::create(test_config("app")).unwrap();

            let key = app
                .generate_key("test@example.com".to_owned())
                .generate()
                .unwrap();

            let qrcode = app
                .get_qr(
                    "test@example.com".to_owned(),
                    None,
                    None,
                    &UserHandle::from_hex(&key.cert.fingerprint).unwrap(),
                    full,
                )
                .unwrap();

            let res = app.verify_qr_all_certs(&qrcode).unwrap();

            assert_eq!(res.content.unwrap().resource, "test@example.com");
            assert_eq!(res.fingerprints.len(), 1);
        }
    }

    #[test]
    fn qr_code_fingerprint() {
        for full in [false, true] {
            let app = PgpApp::create(test_config("app")).unwrap();

            let key = app
                .generate_key("test@example.com".to_owned())
                .name("test".to_owned())
                .generate()
                .unwrap();

            let qrcode = app
                .get_qr(
                    "test@example.com".to_owned(),
                    None,
                    None,
                    &UserHandle::from_hex(&key.cert.fingerprint).unwrap(),
                    full,
                )
                .unwrap();

            let res = app.verify_qr_all_certs(&qrcode).unwrap();

            println!("{:?}", res.fingerprints);

            if full {
                let nk = res.key.unwrap();
                let nk = app
                    .pgp
                    .store
                    .lookup_by_cert_fpr(&Fingerprint::from_hex(&nk.cert.fingerprint).unwrap())
                    .unwrap();
                assert_eq!(nk.fingerprint().to_hex(), key.cert.fingerprint);
                let userids = nk.userids().next().unwrap();
                let userid = userids.name().unwrap().unwrap();
                assert_eq!(userid, "test");
            }

            assert_eq!(res.fingerprints[0], key.cert.fingerprint);
        }
    }

    #[test]
    fn verify_missing_key() {
        for full in [true, false] {
            let app = PgpApp::create(test_config("app1")).unwrap();
            let app2 = PgpApp::create(test_config("app2")).unwrap();

            let key = app
                .generate_key("test@example.com".to_owned())
                .generate()
                .unwrap();

            let qrcode = app
                .get_qr(
                    "test@example.com".to_owned(),
                    None,
                    None,
                    &UserHandle::from_hex(&key.cert.fingerprint).unwrap(),
                    full,
                )
                .unwrap();

            let res = app2.verify_qr_all_certs(&qrcode).unwrap();

            println!("{:?}", res.fingerprints);

            assert_eq!(res.fingerprints[0], key.cert.fingerprint);
        }
    }

    #[test]
    fn strip_cert_is_stub() {
        let app = PgpApp::create(test_config("app1")).unwrap();
        let app2 = PgpApp::create(test_config("app2")).unwrap();

        let key = app
            .generate_key("test@example.com".to_owned())
            .generate()
            .unwrap();

        let cert = app
            .pgp
            .store
            .lookup_by_cert_fpr(&Fingerprint::from_hex(&key.cert.fingerprint).unwrap())
            .unwrap();

        let strip = strip_cert(cert.to_cert().unwrap().clone()).unwrap();

        app2.pgp
            .store
            .update(Arc::new(LazyCert::from_cert(strip.clone())))
            .unwrap();
        let cert = cert.to_cert().unwrap();
        assert_ne!(strip, *cert);
        let is_stub = app.is_stub(&key.cert.fingerprint).unwrap();
        assert!(!is_stub);
        let is_stub = app2.is_stub(&key.cert.fingerprint).unwrap();
        assert!(is_stub);
    }

    #[test]
    fn verify_is_stub() {
        let app = PgpApp::create(test_config("app1")).unwrap();
        let app2 = PgpApp::create(test_config("app2")).unwrap();

        let key = app
            .generate_key("test@example.com".to_owned())
            .generate()
            .unwrap();

        let qrcode = app
            .get_qr(
                "test@example.com".to_owned(),
                None,
                None,
                &UserHandle::from_hex(&key.cert.fingerprint).unwrap(),
                true,
            )
            .unwrap();

        let verify = app2.verify_qr_all_certs(&qrcode).unwrap();

        assert!(verify.is_stub);

        // let verify = app2.verify_qr_all_certs(&qrcode).unwrap();

        // assert!(!verify.is_stub);

        let qrcode = app
            .get_qr(
                "test@example.com".to_owned(),
                None,
                None,
                &UserHandle::from_hex(&key.cert.fingerprint).unwrap(),
                true,
            )
            .unwrap();

        let verify = app.verify_qr_all_certs(&qrcode).unwrap();

        assert!(!verify.is_stub);
        let cert = app
            .pgp
            .store
            .lookup_by_cert_fpr(&Fingerprint::from_hex(&key.cert.fingerprint).unwrap())
            .unwrap();

        app2.pgp.store.update(cert).unwrap();

        let verify = app2.verify_qr_all_certs(&qrcode).unwrap();

        assert!(!verify.is_stub);
    }
}
