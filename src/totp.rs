use std::time::{UNIX_EPOCH, SystemTime};

use anyhow::Context;
use openssl::{
  md::Md,
  md_ctx::MdCtx,
  pkey::PKey
};

use base32::Alphabet;

pub type EpochTime = u64;

pub mod defaults {
  use super::EpochTime;
  pub const START_TIME: EpochTime = 0;
  pub const CODE_WIDTH: u8 = 6;
  pub const STEP_SIZE: u8 = 30;
}

#[derive(Debug)]
pub struct Secret {
  buffer: Vec<u8>
}

impl Secret {
  pub fn from_base32(secret: &str) -> Option<Secret> {
    match base32::decode(Alphabet::RFC4648 { padding: true }, secret) {
      Some(buffer) => Some(Secret{buffer}),
      None => None
    }
  }
}

// hotp dynamic trauncation factor
fn get_hotp_dt(hmac_bytes: &[u8]) -> u32 {
  let offset = (hmac_bytes[19] & 0xF) as usize;

  return
      ((hmac_bytes[offset + 0] as u32) << 24) +
      ((hmac_bytes[offset + 1] as u32) << 16) +
      ((hmac_bytes[offset + 2] as u32) <<  8) +
      ((hmac_bytes[offset + 3] as u32) <<  0);
}

// hotp compute
fn get_hotp(secret: &Secret, time_step: u64, code_width: u8) -> Result<u32, anyhow::Error> {
  let hmac_vec = (|| -> Result<Vec<u8>, anyhow::Error>{
    let key = PKey::hmac(secret.buffer.as_slice())?;

    let mut ctx = MdCtx::new()?;
    ctx.digest_sign_init(Some(Md::sha1()), &key)?;
    ctx.digest_sign_update(&time_step.to_be_bytes())?;
    let mut hmac = vec![];
    ctx.digest_sign_final_to_vec(&mut hmac)?;

    return Ok(hmac);
  })().context("Failed to generate HMAC Hash")?;

  let full_code = get_hotp_dt(&hmac_vec[..]);

  return Ok(full_code % 10_u32.pow(code_width as u32));
}

fn unix_time() -> Result<u64, anyhow::Error> {
  Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

// totp timestep compute
pub fn get_totp_step(start_time: EpochTime, step_size: u8) -> Result<u64, anyhow::Error> {
  assert!(step_size > 0);

  // floor division
  return Ok((unix_time()? - start_time) / (step_size as EpochTime));
}

// totp timestep remainder
pub fn get_totp_remainder(start_time: EpochTime, step_size: EpochTime) -> Result<EpochTime, anyhow::Error> {
  return Ok(step_size - ((unix_time()? - start_time) % step_size));
}

// totp compute
pub fn get_totp_ext(secret: &Secret, start_time: Option<EpochTime>, step_size: Option<u8>, code_width: Option<u8>) -> Result<u32, anyhow::Error> {
  let time_step = get_totp_step(
    start_time.unwrap_or(defaults::START_TIME),
    step_size.unwrap_or(defaults::STEP_SIZE)
  ).context("Failed to get current unix time from system")?;

  return Ok(get_hotp(secret, time_step, code_width.unwrap_or(defaults::CODE_WIDTH))?);
}

pub fn get_totp(secret: &Secret) -> Result<u32, anyhow::Error> {
  return get_totp_ext(secret, None, None, None);
}