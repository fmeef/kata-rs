use std::fs::File;

use sequoia_cert_store::{Store, StoreUpdate};
use sequoia_openpgp::armor::{Kind, Writer};

use crate::api::pgp::PgpServiceStore;

impl<T> PgpServiceStore<T>
where
    T: Send + Sync + Store<'static> + StoreUpdate<'static> + 'static,
{
    pub fn export_file(&self, file: &str) -> anyhow::Result<()> {
        let mut file = File::options().create(true).write(true).open(file)?;
        for cert in self.store.read().certs() {
            cert.export(&mut file)?;
        }
        Ok(())
    }

    pub fn export_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut pile = Vec::new();
        for cert in self.store.read().certs() {
            cert.export(&mut pile)?;
        }
        Ok(pile)
    }

    pub fn export_armor(&self) -> anyhow::Result<String> {
        let bytes = self.export_bytes()?;
        let out = Writer::new(bytes, Kind::PublicKey)?;
        Ok(String::from_utf8(out.finalize()?)?)
    }
}

#[cfg(test)]
mod test {
    use tempfile::NamedTempFile;

    use crate::api::{
        pgp::{import::PgpImportFile, test_config, PgpServiceTrait},
        PgpApp, PgpAppTrait,
    };

    #[test]
    fn test_export() {
        let file = NamedTempFile::new().unwrap();
        let service = PgpApp::create(test_config("app")).unwrap();
        service
            .generate_key("test@example.com".to_owned())
            .generate()
            .unwrap();
        service
            .generate_key("test2@example.com".to_owned())
            .generate()
            .unwrap();
        let path = file.path().to_string_lossy();
        service.export_file(&path).unwrap();
        service
            .import_certs(&PgpImportFile::new(&path).unwrap())
            .unwrap();
    }
}
