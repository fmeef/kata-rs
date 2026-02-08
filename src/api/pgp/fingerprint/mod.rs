use anyhow::anyhow;
use flutter_rust_bridge::frb;
use latkerlo_jvotci::{jvozba::get_lujvo_from_list, Settings};
use lazy_static::lazy_static;
use sequoia_openpgp::Fingerprint;

use crate::{api::pgp::UserHandle, error::InternalErr};

pub mod string;

const EMOJI: [&'static [u8]; 333] = [
    b"\xf0\x9f\x98\x89",
    b"\xf0\x9f\x98\x8d",
    b"\xf0\x9f\x98\x9b",
    b"\xf0\x9f\x98\xad",
    b"\xf0\x9f\x98\xb1",
    b"\xf0\x9f\x98\xa1",
    b"\xf0\x9f\x98\x8e",
    b"\xf0\x9f\x98\xb4",
    b"\xf0\x9f\x98\xb5",
    b"\xf0\x9f\x98\x88",
    b"\xf0\x9f\x98\xac",
    b"\xf0\x9f\x98\x87",
    b"\xf0\x9f\x98\x8f",
    b"\xf0\x9f\x91\xae",
    b"\xf0\x9f\x91\xb7",
    b"\xf0\x9f\x92\x82",
    b"\xf0\x9f\x91\xb6",
    b"\xf0\x9f\x91\xa8",
    b"\xf0\x9f\x91\xa9",
    b"\xf0\x9f\x91\xb4",
    b"\xf0\x9f\x91\xb5",
    b"\xf0\x9f\x98\xbb",
    b"\xf0\x9f\x98\xbd",
    b"\xf0\x9f\x99\x80",
    b"\xf0\x9f\x91\xba",
    b"\xf0\x9f\x99\x88",
    b"\xf0\x9f\x99\x89",
    b"\xf0\x9f\x99\x8a",
    b"\xf0\x9f\x92\x80",
    b"\xf0\x9f\x91\xbd",
    b"\xf0\x9f\x92\xa9",
    b"\xf0\x9f\x94\xa5",
    b"\xf0\x9f\x92\xa5",
    b"\xf0\x9f\x92\xa4",
    b"\xf0\x9f\x91\x82",
    b"\xf0\x9f\x91\x80",
    b"\xf0\x9f\x91\x83",
    b"\xf0\x9f\x91\x85",
    b"\xf0\x9f\x91\x84",
    b"\xf0\x9f\x91\x8d",
    b"\xf0\x9f\x91\x8e",
    b"\xf0\x9f\x91\x8c",
    b"\xf0\x9f\x91\x8a",
    b"\xe2\x9c\x8c",
    b"\xe2\x9c\x8b",
    b"\xf0\x9f\x91\x90",
    b"\xf0\x9f\x91\x86",
    b"\xf0\x9f\x91\x87",
    b"\xf0\x9f\x91\x89",
    b"\xf0\x9f\x91\x88",
    b"\xf0\x9f\x99\x8f",
    b"\xf0\x9f\x91\x8f",
    b"\xf0\x9f\x92\xaa",
    b"\xf0\x9f\x9a\xb6",
    b"\xf0\x9f\x8f\x83",
    b"\xf0\x9f\x92\x83",
    b"\xf0\x9f\x91\xab",
    b"\xf0\x9f\x91\xa8\xe2\x80\x8d\xf0\x9f\x91\xa9\xe2\x80\x8d\xf0\x9f\x91\xa6",
    b"\xf0\x9f\x91\xac",
    b"\xf0\x9f\x91\xad",
    b"\xf0\x9f\x92\x85",
    b"\xf0\x9f\x8e\xa9",
    b"\xf0\x9f\x91\x91",
    b"\xf0\x9f\x91\x92",
    b"\xf0\x9f\x91\x9f",
    b"\xf0\x9f\x91\x9e",
    b"\xf0\x9f\x91\xa0",
    b"\xf0\x9f\x91\x95",
    b"\xf0\x9f\x91\x97",
    b"\xf0\x9f\x91\x96",
    b"\xf0\x9f\x91\x99",
    b"\xf0\x9f\x91\x9c",
    b"\xf0\x9f\x91\x93",
    b"\xf0\x9f\x8e\x80",
    b"\xf0\x9f\x92\x84",
    b"\xf0\x9f\x92\x9b",
    b"\xf0\x9f\x92\x99",
    b"\xf0\x9f\x92\x9c",
    b"\xf0\x9f\x92\x9a",
    b"\xf0\x9f\x92\x8d",
    b"\xf0\x9f\x92\x8e",
    b"\xf0\x9f\x90\xb6",
    b"\xf0\x9f\x90\xba",
    b"\xf0\x9f\x90\xb1",
    b"\xf0\x9f\x90\xad",
    b"\xf0\x9f\x90\xb9",
    b"\xf0\x9f\x90\xb0",
    b"\xf0\x9f\x90\xb8",
    b"\xf0\x9f\x90\xaf",
    b"\xf0\x9f\x90\xa8",
    b"\xf0\x9f\x90\xbb",
    b"\xf0\x9f\x90\xb7",
    b"\xf0\x9f\x90\xae",
    b"\xf0\x9f\x90\x97",
    b"\xf0\x9f\x90\xb4",
    b"\xf0\x9f\x90\x91",
    b"\xf0\x9f\x90\x98",
    b"\xf0\x9f\x90\xbc",
    b"\xf0\x9f\x90\xa7",
    b"\xf0\x9f\x90\xa5",
    b"\xf0\x9f\x90\x94",
    b"\xf0\x9f\x90\x8d",
    b"\xf0\x9f\x90\xa2",
    b"\xf0\x9f\x90\x9b",
    b"\xf0\x9f\x90\x9d",
    b"\xf0\x9f\x90\x9c",
    b"\xf0\x9f\x90\x9e",
    b"\xf0\x9f\x90\x8c",
    b"\xf0\x9f\x90\x99",
    b"\xf0\x9f\x90\x9a",
    b"\xf0\x9f\x90\x9f",
    b"\xf0\x9f\x90\xac",
    b"\xf0\x9f\x90\x8b",
    b"\xf0\x9f\x90\x90",
    b"\xf0\x9f\x90\x8a",
    b"\xf0\x9f\x90\xab",
    b"\xf0\x9f\x8d\x80",
    b"\xf0\x9f\x8c\xb9",
    b"\xf0\x9f\x8c\xbb",
    b"\xf0\x9f\x8d\x81",
    b"\xf0\x9f\x8c\xbe",
    b"\xf0\x9f\x8d\x84",
    b"\xf0\x9f\x8c\xb5",
    b"\xf0\x9f\x8c\xb4",
    b"\xf0\x9f\x8c\xb3",
    b"\xf0\x9f\x8c\x9e",
    b"\xf0\x9f\x8c\x9a",
    b"\xf0\x9f\x8c\x99",
    b"\xf0\x9f\x8c\x8e",
    b"\xf0\x9f\x8c\x8b",
    b"\xe2\x9a\xa1",
    b"\xe2\x98\x94",
    b"\xe2\x9d\x84",
    b"\xe2\x9b\x84",
    b"\xf0\x9f\x8c\x80",
    b"\xf0\x9f\x8c\x88",
    b"\xf0\x9f\x8c\x8a",
    b"\xf0\x9f\x8e\x93",
    b"\xf0\x9f\x8e\x86",
    b"\xf0\x9f\x8e\x83",
    b"\xf0\x9f\x91\xbb",
    b"\xf0\x9f\x8e\x85",
    b"\xf0\x9f\x8e\x84",
    b"\xf0\x9f\x8e\x81",
    b"\xf0\x9f\x8e\x88",
    b"\xf0\x9f\x94\xae",
    b"\xf0\x9f\x8e\xa5",
    b"\xf0\x9f\x93\xb7",
    b"\xf0\x9f\x92\xbf",
    b"\xf0\x9f\x92\xbb",
    b"\xe2\x98\x8e",
    b"\xf0\x9f\x93\xa1",
    b"\xf0\x9f\x93\xba",
    b"\xf0\x9f\x93\xbb",
    b"\xf0\x9f\x94\x89",
    b"\xf0\x9f\x94\x94",
    b"\xe2\x8f\xb3",
    b"\xe2\x8f\xb0",
    b"\xe2\x8c\x9a",
    b"\xf0\x9f\x94\x92",
    b"\xf0\x9f\x94\x91",
    b"\xf0\x9f\x94\x8e",
    b"\xf0\x9f\x92\xa1",
    b"\xf0\x9f\x94\xa6",
    b"\xf0\x9f\x94\x8c",
    b"\xf0\x9f\x94\x8b",
    b"\xf0\x9f\x9a\xbf",
    b"\xf0\x9f\x9a\xbd",
    b"\xf0\x9f\x94\xa7",
    b"\xf0\x9f\x94\xa8",
    b"\xf0\x9f\x9a\xaa",
    b"\xf0\x9f\x9a\xac",
    b"\xf0\x9f\x92\xa3",
    b"\xf0\x9f\x94\xab",
    b"\xf0\x9f\x94\xaa",
    b"\xf0\x9f\x92\x8a",
    b"\xf0\x9f\x92\x89",
    b"\xf0\x9f\x92\xb0",
    b"\xf0\x9f\x92\xb5",
    b"\xf0\x9f\x92\xb3",
    b"\xe2\x9c\x89",
    b"\xf0\x9f\x93\xab",
    b"\xf0\x9f\x93\xa6",
    b"\xf0\x9f\x93\x85",
    b"\xf0\x9f\x93\x81",
    b"\xe2\x9c\x82",
    b"\xf0\x9f\x93\x8c",
    b"\xf0\x9f\x93\x8e",
    b"\xe2\x9c\x92",
    b"\xe2\x9c\x8f",
    b"\xf0\x9f\x93\x90",
    b"\xf0\x9f\x93\x9a",
    b"\xf0\x9f\x94\xac",
    b"\xf0\x9f\x94\xad",
    b"\xf0\x9f\x8e\xa8",
    b"\xf0\x9f\x8e\xac",
    b"\xf0\x9f\x8e\xa4",
    b"\xf0\x9f\x8e\xa7",
    b"\xf0\x9f\x8e\xb5",
    b"\xf0\x9f\x8e\xb9",
    b"\xf0\x9f\x8e\xbb",
    b"\xf0\x9f\x8e\xba",
    b"\xf0\x9f\x8e\xb8",
    b"\xf0\x9f\x91\xbe",
    b"\xf0\x9f\x8e\xae",
    b"\xf0\x9f\x83\x8f",
    b"\xf0\x9f\x8e\xb2",
    b"\xf0\x9f\x8e\xaf",
    b"\xf0\x9f\x8f\x88",
    b"\xf0\x9f\x8f\x80",
    b"\xe2\x9a\xbd",
    b"\xe2\x9a\xbe",
    b"\xf0\x9f\x8e\xbe",
    b"\xf0\x9f\x8e\xb1",
    b"\xf0\x9f\x8f\x89",
    b"\xf0\x9f\x8e\xb3",
    b"\xf0\x9f\x8f\x81",
    b"\xf0\x9f\x8f\x87",
    b"\xf0\x9f\x8f\x86",
    b"\xf0\x9f\x8f\x8a",
    b"\xf0\x9f\x8f\x84",
    b"\xe2\x98\x95",
    b"\xf0\x9f\x8d\xbc",
    b"\xf0\x9f\x8d\xba",
    b"\xf0\x9f\x8d\xb7",
    b"\xf0\x9f\x8d\xb4",
    b"\xf0\x9f\x8d\x95",
    b"\xf0\x9f\x8d\x94",
    b"\xf0\x9f\x8d\x9f",
    b"\xf0\x9f\x8d\x97",
    b"\xf0\x9f\x8d\xb1",
    b"\xf0\x9f\x8d\x9a",
    b"\xf0\x9f\x8d\x9c",
    b"\xf0\x9f\x8d\xa1",
    b"\xf0\x9f\x8d\xb3",
    b"\xf0\x9f\x8d\x9e",
    b"\xf0\x9f\x8d\xa9",
    b"\xf0\x9f\x8d\xa6",
    b"\xf0\x9f\x8e\x82",
    b"\xf0\x9f\x8d\xb0",
    b"\xf0\x9f\x8d\xaa",
    b"\xf0\x9f\x8d\xab",
    b"\xf0\x9f\x8d\xad",
    b"\xf0\x9f\x8d\xaf",
    b"\xf0\x9f\x8d\x8e",
    b"\xf0\x9f\x8d\x8f",
    b"\xf0\x9f\x8d\x8a",
    b"\xf0\x9f\x8d\x8b",
    b"\xf0\x9f\x8d\x92",
    b"\xf0\x9f\x8d\x87",
    b"\xf0\x9f\x8d\x89",
    b"\xf0\x9f\x8d\x93",
    b"\xf0\x9f\x8d\x91",
    b"\xf0\x9f\x8d\x8c",
    b"\xf0\x9f\x8d\x90",
    b"\xf0\x9f\x8d\x8d",
    b"\xf0\x9f\x8d\x86",
    b"\xf0\x9f\x8d\x85",
    b"\xf0\x9f\x8c\xbd",
    b"\xf0\x9f\x8f\xa1",
    b"\xf0\x9f\x8f\xa5",
    b"\xf0\x9f\x8f\xa6",
    b"\xe2\x9b\xaa",
    b"\xf0\x9f\x8f\xb0",
    b"\xe2\x9b\xba",
    b"\xf0\x9f\x8f\xad",
    b"\xf0\x9f\x97\xbb",
    b"\xf0\x9f\x97\xbd",
    b"\xf0\x9f\x8e\xa0",
    b"\xf0\x9f\x8e\xa1",
    b"\xe2\x9b\xb2",
    b"\xf0\x9f\x8e\xa2",
    b"\xf0\x9f\x9a\xa2",
    b"\xf0\x9f\x9a\xa4",
    b"\xe2\x9a\x93",
    b"\xf0\x9f\x9a\x80",
    b"\xe2\x9c\x88",
    b"\xf0\x9f\x9a\x81",
    b"\xf0\x9f\x9a\x82",
    b"\xf0\x9f\x9a\x8b",
    b"\xf0\x9f\x9a\x8e",
    b"\xf0\x9f\x9a\x8c",
    b"\xf0\x9f\x9a\x99",
    b"\xf0\x9f\x9a\x97",
    b"\xf0\x9f\x9a\x95",
    b"\xf0\x9f\x9a\x9b",
    b"\xf0\x9f\x9a\xa8",
    b"\xf0\x9f\x9a\x94",
    b"\xf0\x9f\x9a\x92",
    b"\xf0\x9f\x9a\x91",
    b"\xf0\x9f\x9a\xb2",
    b"\xf0\x9f\x9a\xa0",
    b"\xf0\x9f\x9a\x9c",
    b"\xf0\x9f\x9a\xa6",
    b"\xe2\x9a\xa0",
    b"\xf0\x9f\x9a\xa7",
    b"\xe2\x9b\xbd",
    b"\xf0\x9f\x8e\xb0",
    b"\xf0\x9f\x97\xbf",
    b"\xf0\x9f\x8e\xaa",
    b"\xf0\x9f\x8e\xad",
    b"\xf0\x9f\x87\xaf\xf0\x9f\x87\xb5",
    b"\xf0\x9f\x87\xb0\xf0\x9f\x87\xb7",
    b"\xf0\x9f\x87\xa9\xf0\x9f\x87\xaa",
    b"\xf0\x9f\x87\xa8\xf0\x9f\x87\xb3",
    b"\xf0\x9f\x87\xba\xf0\x9f\x87\xb8",
    b"\xf0\x9f\x87\xab\xf0\x9f\x87\xb7",
    b"\xf0\x9f\x87\xaa\xf0\x9f\x87\xb8",
    b"\xf0\x9f\x87\xae\xf0\x9f\x87\xb9",
    b"\xf0\x9f\x87\xb7\xf0\x9f\x87\xba",
    b"\xf0\x9f\x87\xac\xf0\x9f\x87\xa7",
    b"\x31\xe2\x83\xa3",
    b"\x32\xe2\x83\xa3",
    b"\x33\xe2\x83\xa3",
    b"\x34\xe2\x83\xa3",
    b"\x35\xe2\x83\xa3",
    b"\x36\xe2\x83\xa3",
    b"\x37\xe2\x83\xa3",
    b"\x38\xe2\x83\xa3",
    b"\x39\xe2\x83\xa3",
    b"\x30\xe2\x83\xa3",
    b"\xf0\x9f\x94\x9f",
    b"\xe2\x9d\x97",
    b"\xe2\x9d\x93",
    b"\xe2\x99\xa5",
    b"\xe2\x99\xa6",
    b"\xf0\x9f\x92\xaf",
    b"\xf0\x9f\x94\x97",
    b"\xf0\x9f\x94\xb1",
    b"\xf0\x9f\x94\xb4",
    b"\xf0\x9f\x94\xb5",
    b"\xf0\x9f\x94\xb6",
    b"\xf0\x9f\x94\xb7",
];

lazy_static! {
    static ref GISMU: Vec<&'static str> = get_gismu();
}

fn get_gismu() -> Vec<&'static str> {
    let gismu = include_str!("gismu.txt");
    gismu.lines().collect()
}

fn bytes_to_n_fair(arr: &[u8], offset: u64, l: u64) -> anyhow::Result<u64> {
    let mut v: u64 = 0;
    if l > u64::MAX || l as usize > arr.len() {
        return Err(anyhow!(InternalErr::Generic("huge")));
    }

    let mut mask = 0x7F;

    for n in 0..l {
        let shift = (l - 1) * 8 - n * 8;
        v = v | ((arr[(offset + n) as usize] as u64 & mask) << shift);

        mask = 0xFF;
    }

    Ok(v)
}

fn data_to_emoji(data: &[u8]) -> anyhow::Result<Vec<String>> {
    let n = ((EMOJI.len() as f64).log2() / 8.0).ceil() as u64;
    let mut out = Vec::new();
    for i in 0..(data.len() as f64 / n as f64).ceil() as u64 {
        let sel = bytes_to_n_fair(data, i * n, n)? as usize % EMOJI.len();
        let emoji = String::from_utf8_lossy(EMOJI[sel]);
        out.push(emoji.into_owned());
    }

    Ok(out)
}

fn data_to_gismu(data: &[u8]) -> anyhow::Result<Vec<String>> {
    let n = ((GISMU.len() as f64).log2() / 8.0).ceil() as u64;
    let mut out = Vec::new();

    for i in 0..(data.len() as f64 / n as f64).ceil() as u64 {
        let sel = bytes_to_n_fair(data, i * n, n)? as usize % GISMU.len();
        out.push(GISMU[sel].to_owned());
    }

    Ok(out)
}

fn data_to_gismu_2(data: &[u8]) -> anyhow::Result<Vec<(String, Option<String>)>> {
    let n = ((GISMU.len() as f64).log2() / 8.0).ceil() as u64;
    let mut out = Vec::new();
    let end = (data.len() as f64 / n as f64).ceil() as u64;
    for i in (0..end).step_by(2) {
        if i + 1 < end {
            let sel = bytes_to_n_fair(data, i * n, n)? as usize % GISMU.len();
            let sel2 = bytes_to_n_fair(data, (i + 1) * n, n)? as usize % GISMU.len();
            out.push((GISMU[sel].to_owned(), Some(GISMU[sel2].to_owned())));
        } else {
            let sel = bytes_to_n_fair(data, i * n, n)? as usize % GISMU.len();
            out.push((GISMU[sel].to_owned(), None));
        }
    }

    Ok(out)
}

fn lujvo_combined(data: &[u8]) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();
    for (g1, g2) in data_to_gismu_2(data)? {
        match g2 {
            Some(g2) => {
                let l =
                    get_lujvo_from_list(&[g1, g2], &Settings::default()).map_err(|v| anyhow!(v))?;
                out.push(l.0);
            }
            None => {
                out.push(g1);
            }
        }
    }
    Ok(out)
}

fn data_to_phone(data: &[u8]) -> anyhow::Result<String> {
    if data.len() != 4 {
        return Err(anyhow!(InternalErr::Generic("wrong length for phone")));
    }

    let v = bytes_to_n_fair(data, 0, 4)? % 9999999999;

    let country = (v / (10 as u64).pow(9)) as u32 + 1;
    let number = (v % (10 as u64).pow(9)) as u32;
    let area = (number / (10 as u32).pow(7)) as u32;
    let number = (number % (10 as u32).pow(7)) as u32;
    let middle = (number / (10 as u32).pow(4)) as u32;
    let end = (number % (10 as u32).pow(4)) as u32;

    Ok(format!("+{country} 8{area:02}-{middle:03}-{end:04}"))
}

pub struct VisualKey {
    pub gismu: Vec<String>,
    pub emoji: Vec<String>,
    pub phone: String,
}

impl UserHandle {
    #[frb(sync)]
    pub fn separate(&self) -> anyhow::Result<VisualKey> {
        let fp = self.as_bytes();

        if fp.len() < 20 {
            return Err(anyhow!(InternalErr::Generic(
                "data too small for composite"
            )));
        }

        let gismu = data_to_gismu(&fp[0..8])?;
        let emoji = data_to_emoji(&fp[8..16])?;
        let phone = data_to_phone(&fp[16..20])?;

        Ok(VisualKey {
            gismu,
            emoji,
            phone,
        })
    }

    #[frb(sync)]
    pub fn separate_lujvo(&self) -> anyhow::Result<VisualKey> {
        let fp = self.as_bytes();

        if fp.len() < 20 {
            return Err(anyhow!(InternalErr::Generic(
                "data too small for composite"
            )));
        }

        let gismu = data_to_gismu(&fp[0..16])?;
        let emoji = Vec::new();
        let phone = data_to_phone(&fp[16..20])?;

        Ok(VisualKey {
            gismu,
            emoji,
            phone,
        })
    }

    #[frb(sync)]
    pub fn composite_lujvo(&self, short: bool) -> anyhow::Result<String> {
        let fp = self.as_bytes();

        if fp.len() < 20 {
            return Err(anyhow!(InternalErr::Generic(
                "data too small for composite"
            )));
        }

        let lujvo = lujvo_combined(&fp[0..16])?.join(" ");
        let phone = data_to_phone(&fp[16..20])?;
        if short {
            Ok(lujvo)
        } else {
            Ok(format!("{lujvo} ({phone})"))
        }
    }

    #[frb(sync)]
    pub fn composite_lujvo_or_else(&self, short: bool) -> String {
        self.composite_lujvo(short).unwrap_or_else(|_| self.name())
    }

    #[frb(sync)]
    pub fn composite(&self) -> anyhow::Result<String> {
        let fp = self.as_bytes();

        if fp.len() < 20 {
            return Err(anyhow!(InternalErr::Generic(
                "data too small for composite"
            )));
        }

        let gismu = data_to_gismu(&fp[0..8])?.join(" ");
        let emoji = data_to_emoji(&fp[8..16])?.join(" ");
        let phone = data_to_phone(&fp[16..20])?;

        Ok(format!("{gismu} {emoji} ({phone})"))
    }
}

#[cfg(test)]
mod test {
    use crate::api::pgp::UserHandle;

    #[test]
    fn gismu_emoji_phone_fingerprint() {
        let v = UserHandle::from_hex("9FCF6558AC4927F1E7A43D80317375B449854036").unwrap();
        let c = v.composite().unwrap();
        assert_eq!(c, "canja jeftu krixa pensi 🍴 🐗 😡 💡 (+2 823-346-9494)");
    }

    #[test]
    fn lujvo_emoji_phone_fingerprint() {
        let v = UserHandle::from_hex("9FCF6558AC4927F1E7A43D80317375B449854036").unwrap();
        let c = v.composite_lujvo().unwrap();
        assert_eq!(c, "cajyjeftu kixpei nansne kitladru (+2 823-346-9494)");
    }
}
