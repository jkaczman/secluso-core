use std::fs::File;
use std::{io, thread};
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;
use rand::Rng;
use secluso_client_lib::pairing::MAX_ALLOWED_MSG_LEN;
use secluso_client_server_lib::auth::parse_user_credentials_full;

// Used to generate random names.
// With 16 alphanumeric characters, the probability of collision is very low.
// Note: even if collision happens, it has no impact on
// our security guarantees. Will only cause availability issues.
pub(crate) const NUM_RANDOM_CHARS: u8 = 16;


/// Returns username, password, and server addr
pub fn read_parse_full_credentials() -> (String, String, String) {
    let file = File::open("credentials_full").expect("Could not open user_credentials file");
    let mut reader =
        BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
    let data = reader.fill_buf().unwrap();

    let credentials_full_bytes = data.to_vec();

    let (server_username, server_password, server_addr) =
        parse_user_credentials_full(credentials_full_bytes).unwrap();

    (server_username, server_password, server_addr)
}


/// Utility function for outside the pairing module
pub fn get_names(
    state_dir: String,
    first_time: bool,
    camera_filename: String,
    group_filename: String,
) -> anyhow::Result<(String, String)> {
    let state_dir_path = Path::new(&state_dir);
    let camera_path = state_dir_path.join(camera_filename);
    let group_path = state_dir_path.join(group_filename);

    let (camera_name, group_name) = if first_time {
        let mut rng = rand::rng();
        let cname: String = (0..NUM_RANDOM_CHARS)
            .map(|_| rng.sample(rand::distr::Alphanumeric) as char)
            .collect();

        let mut file = File::create(camera_path).expect("Could not create file");
        file.write_all(cname.as_bytes())?;
        file.flush()?;
        file.sync_all()?;

        let gname: String = (0..NUM_RANDOM_CHARS)
            .map(|_| rng.sample(rand::distr::Alphanumeric) as char)
            .collect();

        file = File::create(group_path).expect("Could not create file");
        file.write_all(gname.as_bytes())?;
        file.flush()?;
        file.sync_all()?;

        (cname, gname)
    } else {
        let file = File::open(camera_path).expect("Cannot open file to send");
        let mut reader =
            BufReader::with_capacity(file.metadata()?.len() as usize, file);
        let cname = reader.fill_buf()?;

        let file = File::open(group_path).expect("Cannot open file to send");
        let mut reader =
            BufReader::with_capacity(file.metadata()?.len() as usize, file);
        let gname = reader.fill_buf()?;

        (
            String::from_utf8(cname.to_vec())?,
            String::from_utf8(gname.to_vec())?,
        )
    };

    Ok((camera_name, group_name))
}

// TODO: This is a duplicate of the code in app_native.
pub(crate) fn write_varying_len(stream: &mut TcpStream, msg: &[u8]) -> io::Result<()> {
    // FIXME: is u64 necessary?
    let len = msg.len() as u64;
    let len_data = len.to_be_bytes();

    stream.write_all(&len_data)?;
    stream.write_all(msg)?;
    stream.flush()?;

    Ok(())
}

// TODO: This is a duplicate of the code in app_native.
pub(crate) fn read_varying_len(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut len_data = [0u8; 8];

    match stream.read_exact(&mut len_data) {
        Ok(_) => {}
        Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
            return Err(io::Error::new(
                ErrorKind::WouldBlock,
                "Length read would block",
            ));
        }
        Err(e) => return Err(e),
    }

    let len = u64::from_be_bytes(len_data);

    if len > MAX_ALLOWED_MSG_LEN {
        error!("Communicated message length ({len}) exceeds the allowed length ({MAX_ALLOWED_MSG_LEN})");
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "Intended message length is too large",
        ));
    }

    let mut msg = vec![0u8; len as usize];
    let mut offset = 0;

    while offset < msg.len() {
        match stream.read(&mut msg[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "Socket closed during read",
                ))
            }
            Ok(n) => {
                offset += n;
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                // retry a few times with a short delay
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(msg)
}