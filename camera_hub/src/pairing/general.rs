use crate::initialize_mls_clients;

cfg_if::cfg_if! {
    if #[cfg(feature = "raspberry")] {
        use secluso_client_lib::http_client::HttpClient;
        use crate::pairing::wifi::{self, create_wifi_hotspot};
        use std::process::Command;
    }
}

use crate::traits::Camera;
use crate::version::camera_version_info;
use openmls::key_packages::KeyPackage;
use secluso_client_lib::mls_client::MlsClient;
use secluso_client_lib::mls_clients::{MlsClients, CONFIG};
use secluso_client_lib::pairing::{self, generate_ip_camera_secret};
use std::fs::File;
use std::io::{BufRead, BufReader, ErrorKind};
use std::net::{TcpListener, TcpStream};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use std::{fs, io};

// Used to ensure there can't be attempted concurrent pairing
static LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[allow(clippy::too_many_arguments)]
pub fn pair_all(
    camera: &dyn Camera,
    mls_clients: &mut MlsClients,
    input_camera_secret: Option<Vec<u8>>,
) -> anyhow::Result<()> {
    // Ensure that two cameras don't attempt to pair at the same time (as this would introduce an error when opening two of the same port simultaneously)
    let _lock = LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("Another user of the LOCK mutex panicked while holding the mutex");

    // If None, this has to be an IP camera. If the camera_secret does not exist for Raspberry Pi, it will not proceed earlier on in the flow.
    #[cfg(feature = "raspberry")]
    assert!(
        input_camera_secret.is_none(),
        "A Raspberry Pi camera must have a camera secret"
    );

    let (secret, message) = match input_camera_secret.clone() {
        Some(s) => {
            (s, "Use the camera QR code in the app to pair.".to_owned())
        }
        None => {
            (
                generate_ip_camera_secret(&camera.get_name())?,
                format!("[{}] File camera_{}_secret_qrcode.png was just created. Use the QR code in the app to pair.", camera.get_name(), camera.get_name().replace(' ', "_").to_lowercase())
            )
        }
    };
    println!("{message}");

    // Loop and continuously try to pair with the app (in case of failures)
    let listener = TcpListener::bind("0.0.0.0:12348")?;
    for incoming in listener.incoming() {
        match incoming {
            Ok(mut stream) => {
                debug!("[Pairing] Incoming connection accepted.");

                if let Err(e) = stream.set_nonblocking(false) {
                    debug!("[Pairing] Failed to set blocking mode: {e}");
                }

                if let Err(e) = stream.set_read_timeout(Some(Duration::from_secs(10))) {
                    debug!("[Pairing] Failed to set read timeout: {e}");
                }

                if let Err(e) = stream.set_write_timeout(Some(Duration::from_secs(10))) {
                    debug!("[Pairing] Failed to set write timeout: {e}");
                }

                if try_pairing(&mut stream, mls_clients, &secret, camera) {
                    // Pairing was successful!
                    break;
                }

                // Get rid of any potential failed pairs beforehand.
                for mls_client in mls_clients.iter_mut() {
                    mls_client.clean()?;
                }

                // We cannot use the old user objects, so create new clients.
                *mls_clients = initialize_mls_clients(camera, true)?;

                debug!("[Pairing] Error — resetting for next connection");
            }

            Err(e) => {
                debug!("[Pairing] Incoming connection error: {e}");
            }
        }
    }

    if input_camera_secret.is_none() {
        let _ = fs::remove_file(format!(
            "camera_{}_secret_qrcode.png",
            camera.get_name().replace(' ', "_").to_lowercase()
        ));
    }

    Ok(())
}

fn try_pairing(
    stream: &mut TcpStream,
    mls_clients: &mut MlsClients,
    secret: &[u8],
    camera: &dyn Camera,
) -> bool {
    // Receive timestamp and set system date and time.
    // This is because an RPi doesn't have a battery-backed real-time clock.
    // Therefore, if it remains off before pairing, its wall clock will be off.
    // This then prevents successful pairing due to MLS checking the lifetime
    // of key packages.
    #[cfg(feature = "raspberry")]
    if let Err(e) = receive_timestamp_set_system_time(stream) {
        debug!("[Pairing] Failed to receive and set timestamp: {e}");
        return false;
    }

    debug!("[Pairing] Before sending firmware version");
    if let Err(e) = send_firmware_version(stream) {
        debug!("[Pairing] Failed to send firmware_version: {e}");
        return false;
    }

    debug!("[Pairing] Before pairing");
    for mls_client in mls_clients.iter_mut() {
        match perform_pairing_handshake(stream, mls_client.key_package()) {
            Ok(app_key_package) => {
                if let Err(e) = invite(stream, mls_client, app_key_package, secret.to_owned()) {
                    debug!("[Pairing] Failed to create group: {e}");
                    return false;
                }
            }
            Err(e) => {
                debug!("[Pairing] Pairing failed: {e}");
                return false;
            }
        }
    }

    #[cfg(feature = "raspberry")]
    {
        debug!("[Pairing] Before receiving credentials");
        match wifi::receive_credentials_full(stream, &mut mls_clients[CONFIG]) {
            Ok(()) => {}
            Err(e) => {
                debug!("[Pairing] Failed to receive credentials_full: {e}");
                return false;
            }
        }

        debug!("[Pairing] Before parsing credentials");
        let (server_username, server_password, server_addr) =
        crate::pairing::io::read_parse_full_credentials();
        let http_client = HttpClient::new(server_addr.clone(), server_username, server_password);


        let (changed_wifi, success) = wifi::attempt_wifi_pair(
            stream,
            mls_clients,
            &http_client,
            camera,
            server_addr.as_str(),
        );

        if changed_wifi && !success {
            debug!("[Pairing] Creating WiFi hotspot after fail");
            create_wifi_hotspot();

            return false;
        }
    }
    true
}

fn send_firmware_version(stream: &mut TcpStream) -> io::Result<()> {
    let msg = serde_json::to_vec(&camera_version_info()?)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e.to_string()))?;
    crate::pairing::io::write_varying_len(stream, &msg)?;

    Ok(())
}

fn invite(
    stream: &mut TcpStream,
    mls_client: &mut MlsClient,
    app_key_package: KeyPackage,
    camera_secret: Vec<u8>,
) -> io::Result<()> {
    let app_contact = MlsClient::create_contact("app", app_key_package)?;
    debug!("Added contact.");

    let (welcome_msg_vec, _, _) = mls_client
        .invite_with_secret(&app_contact, camera_secret)
        .inspect_err(|_| {
            error!("invite() returned error:");
        })?;
    mls_client.save_group_state()?;
    debug!("App invited to the group.");

    crate::pairing::io::write_varying_len(stream, &welcome_msg_vec)?;

    // Next, send the shared group name
    let group_name = mls_client.get_group_name()?;
    crate::pairing::io::write_varying_len(stream, group_name.as_bytes())?;

    Ok(())
}

#[cfg(feature = "raspberry")]
fn receive_timestamp_set_system_time(stream: &mut TcpStream) -> anyhow::Result<()> {
    let timestamp_vec = crate::pairing::io::read_varying_len(stream)?;
    let timestamp: u64 = bincode::deserialize(&timestamp_vec)?;
    let _ = Command::new("date")
        .arg("-s")
        .arg(format!("@{timestamp}"))
        .output()?;

    Ok(())
}

fn perform_pairing_handshake(
    stream: &mut TcpStream,
    camera_key_package: KeyPackage,
) -> anyhow::Result<KeyPackage> {
    let pairing = pairing::Camera::new(camera_key_package);

    let app_msg = crate::pairing::io::read_varying_len(stream)?;
    let (app_key_package, camera_msg) = pairing.process_app_msg_and_generate_msg_to_app(app_msg)?;
    crate::pairing::io::write_varying_len(stream, &camera_msg)?;

    Ok(app_key_package)
}

pub fn get_input_camera_secret() -> Vec<u8> {
    let pathname = match std::env::var("SECLUSO_USE_PROVISION").as_deref() {
        Ok("1") => "/provision/camera_secret",
        _ => "./camera_secret",
    };

    let file = File::open(pathname).expect(
        "Could not open file \"camera_secret\". You can generate this with the config_tool",
    );
    let mut reader =
        BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
    let data = reader.fill_buf().unwrap();

    data.to_vec()
}
