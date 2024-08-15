mod totp;

use std::thread;
use std::time::Duration;
use console::Term;
use crate::totp::*;
use indicatif::ProgressBar;

//https://datatracker.ietf.org/doc/html/rfc6238
//https://datatracker.ietf.org/doc/html/rfc4226

fn get_totp_str(secret: &Secret) -> Result<String,anyhow::Error> {
    Ok(format!("{}", get_totp(&secret)?))
}

fn main() -> Result<(),anyhow::Error> {
    let secret = Secret::from_base32("JBSWY3DPEHPK3PXP").unwrap();

    // test: https://totp.danhersam.com/
    // println!("code: {}", get_totp(&secret)?);
    // println!("expires in {}", get_totp_remainder(0, 30)?);
    let term = Term::stdout();
    let bar = ProgressBar::new(30)
        .with_prefix("Codes expire in")
        .with_position(get_totp_remainder(0, 30)?);
    term.hide_cursor()?;
    loop {
        let time_remaining = get_totp_remainder(0, 30)?;

        bar.set_position(time_remaining);
        term.write_line(&get_totp_str(&secret)?)?;
        term.move_cursor_up(1)?;
        thread::sleep(Duration::from_millis(1000));
    }

    Ok(())
}