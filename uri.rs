#![forbid(unsafe_code)]
use bech32::{ToBase32, FromBase32, Variant};
use thiserror::Error;
use url::Url;

use crate::spend_builder::{AmountZat, Zip324Key};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityUri {
    pub key: Zip324Key,
    pub amount_zat: AmountZat,  // displayed amount (excludes default sweep fee)
    pub desc: Option<String>,
}

#[derive(Error, Debug)]
pub enum UriError {
    #[error("invalid uri")]
    Invalid,
    #[error("bech32 error: {0}")]
    Bech32(#[from] bech32::Error),
    #[error("url parse error: {0}")]
    Url(#[from] url::ParseError),
}

impl CapabilityUri {
    /// Spec‑style form: https://pay.withzcash.com:65536/payment/v1#amount=...&desc=...&key=bech32(key)
    pub fn to_string_with_hrp(&self, hrp: &str) -> Result<String, UriError> {
        let key_b32 = self.key.0.to_base32();
        let key_enc = bech32::encode(hrp, key_b32, Variant::Bech32m)?;
        let mut url = Url::parse("https://pay.withzcash.com:65536/payment/v1")?;
        url.set_fragment(Some(&format!(
            "amount={}&{}key={}",
            self.amount_zat.0,
            self.desc.as_ref().map(|d| format!("desc={}&", urlencoding::encode(d))).unwrap_or_default(),
            key_enc
        )));
        Ok(url.into())
    }

    pub fn parse(s: &str, hrp: &str) -> Result<Self, UriError> {
        let url = Url::parse(s)?;
        let frag = url.fragment().ok_or(UriError::Invalid)?;
        // crude parser over "a=..&b=.."
        let mut amount = None;
        let mut desc = None;
        let mut key_enc = None;
        for kv in frag.split('&') {
            let mut it = kv.splitn(2, '=');
            let k = it.next().unwrap_or_default();
            let v = it.next().unwrap_or_default();
            match k {
                "amount" => amount = v.parse::<u64>().ok(),
                "desc" => desc = Some(urlencoding::decode(v).ok().map(|x| x.into_owned()).unwrap_or_default()),
                "key" => key_enc = Some(v.to_string()),
                _ => {}
            }
        }
        let key_enc = key_enc.ok_or(UriError::Invalid)?;
        let (got_hrp, data, variant) = bech32::decode(&key_enc)?;
        if got_hrp != hrp || variant != Variant::Bech32m { return Err(UriError::Invalid); }
        let bytes = Vec::<u8>::from_base32(&data)?;
        if bytes.len() != 32 { return Err(UriError::Invalid); }
        Ok(Self {
            key: Zip324Key(bytes.try_into().unwrap()),
            amount_zat: AmountZat(amount.ok_or(UriError::Invalid)?),
            desc,
        })
    }
}