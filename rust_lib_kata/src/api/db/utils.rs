use crate::error::AppResult;

#[allow(dead_code)]
pub(crate) trait HexConvert {
    fn to_hex(&self) -> String;
    fn from_hex(hex: &str) -> AppResult<Self>
    where
        Self: Sized;
}

impl HexConvert for Vec<u8> {
    fn from_hex(hex: &str) -> AppResult<Self> {
        Ok(hex::decode(&hex)?)
    }

    fn to_hex(&self) -> String {
        hex::encode(self)
    }
}
