pub use anyhow::Result;
use flutter_rust_bridge::frb;
pub use sequoia_openpgp::cert::CertParser;
pub use sequoia_openpgp::parse::{PacketPileParser, Parse};
pub use sequoia_openpgp::PacketPile;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Mutex;

use std::io::Read;

#[frb(opaque)]
pub struct PgpImportBytes {
    tx: std::sync::mpsc::Sender<Vec<u8>>,
    rx: Mutex<std::sync::mpsc::Receiver<Vec<u8>>>,
    buf: Mutex<Vec<u8>>,
}

#[frb(opaque)]
pub struct PgpImportFile {
    file: PathBuf,
}

impl PgpImportFile {
    #[frb(sync)]
    pub fn new(path: &str) -> anyhow::Result<Self> {
        Ok(Self {
            file: PathBuf::from_str(path)?,
        })
    }
}

struct PgpImportReader<'a>(&'a PgpImportBytes);

impl PgpImportBytes {
    fn get_reader(&self) -> PgpImportReader<'_> {
        PgpImportReader(self)
    }
}

pub trait PgpImport {
    fn get_packets<'a>(&'a self) -> anyhow::Result<CertParser<'a>>;
}

impl PgpImport for PgpImportFile {
    fn get_packets<'a>(&'a self) -> anyhow::Result<CertParser<'a>> {
        let parser = CertParser::from_file(&self.file)?;

        Ok(parser)
    }
}

impl PgpImport for PgpImportBytes {
    fn get_packets<'a>(&'a self) -> anyhow::Result<CertParser<'a>> {
        let reader = self.get_reader();
        let parser = CertParser::from_reader(reader)?;
        Ok(parser)
    }
}

impl PgpImportBytes {
    #[frb(sync)]
    pub fn new() -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        Self {
            tx,
            rx: Mutex::new(rx),
            buf: Mutex::new(Vec::new()),
        }
    }

    pub fn accept(&self, bytes: Vec<u8>) -> anyhow::Result<()> {
        self.tx.send(bytes)?;
        Ok(())
    }
}

impl<'a> Read for PgpImportReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut lock = self.0.buf.lock().unwrap();
        let rx = self.0.rx.lock().unwrap();
        let refbuf: &mut Vec<u8> = lock.as_mut();
        if refbuf.len() >= buf.len() {
            let out = refbuf.drain(refbuf.len() - buf.len()..);
            out.as_slice().read(buf)
        } else {
            let mut new = rx.recv().map_err(|e| std::io::Error::other(e))?;
            if new.len() <= buf.len() {
                new.as_slice().read(buf)
            } else {
                let out = new.drain(0..buf.len()).as_slice().read(buf)?;
                let b = new.drain(0..);
                refbuf.extend_from_slice(b.as_slice());
                Ok(out)
            }
        }
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        let mut lock = self.0.buf.lock().unwrap();

        let refbuf: &mut Vec<u8> = lock.as_mut();
        if refbuf.len() >= buf.len() {
            let out = refbuf.drain(refbuf.len() - buf.len()..);
            out.as_slice().read_exact(buf)
        } else {
            let rx = self.0.rx.lock().unwrap();

            loop {
                let new = rx.recv().map_err(|e| std::io::Error::other(e))?;
                if new.len() == buf.len() {
                    return new.as_slice().read_exact(buf);
                } else if refbuf.len() >= buf.len() {
                    let out = refbuf.drain(refbuf.len() - buf.len()..);
                    return out.as_slice().read_exact(buf);
                } else {
                    refbuf.extend_from_slice(new.as_slice());
                }
            }
        }
    }
}

// impl BufRead for PgpImport {
//     fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
//         todo!()
//     }

//     fn consume(&mut self, amount: usize) {
//         todo!()
//     }
// }

#[cfg(test)]
mod test {
    use std::io::Read;

    use crate::api::pgp::import::PgpImportBytes;

    #[test]
    fn simple_read_exact() {
        let reference: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut out = vec![0; reference.len()];
        let i = PgpImportBytes::new();
        i.accept(reference.clone()).unwrap();
        let mut i = i.get_reader();
        i.read_exact(&mut out).unwrap();
        assert_eq!(out, reference);
    }

    #[test]
    fn simple_read() {
        let reference: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut out = vec![0; reference.len() - 4];
        let i = PgpImportBytes::new();
        i.accept(reference.clone()).unwrap();
        let mut i = i.get_reader();
        i.read(&mut out).unwrap();
        assert_eq!(out[..], reference[..reference.len() - 4]);
        let mut out = vec![0; 4];

        i.read(&mut out).unwrap();

        assert_eq!(out[..], reference[reference.len() - 4..])
    }

    #[test]
    fn multiple_read() {
        let mut i = PgpImportBytes::new();
        for _ in 0..20 {
            let reference: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
            let mut out = vec![0; reference.len() - 4];
            i.accept(reference.clone()).unwrap();
            let mut i = i.get_reader();
            i.read(&mut out).unwrap();
            assert_eq!(out[..], reference[..reference.len() - 4]);
            let mut out = vec![0; 4];

            i.read(&mut out).unwrap();

            assert_eq!(out[..], reference[reference.len() - 4..])
        }
    }

    #[test]
    fn multiple_partial_read() {
        let reference: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let i = PgpImportBytes::new();

        for _ in 0..20 {
            i.accept(reference.clone()).unwrap();
        }

        for _ in 0..20 {
            let mut out = vec![0; reference.len() - 4];
            let mut i = i.get_reader();
            i.read(&mut out).unwrap();
            assert_eq!(out[..], reference[..reference.len() - 4]);
            let mut out = vec![0; 4];

            i.read(&mut out).unwrap();

            assert_eq!(out[..], reference[reference.len() - 4..])
        }
    }

    #[test]
    fn multiple_partial_read_exact() {
        let reference: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let i = PgpImportBytes::new();

        for _ in 0..20 {
            i.accept(reference.clone()).unwrap();
        }

        let mut i = i.get_reader();

        for _ in 0..20 {
            let mut out = vec![0; reference.len()];
            i.read_exact(&mut out).unwrap();
            assert_eq!(out, reference);
        }
    }
}
