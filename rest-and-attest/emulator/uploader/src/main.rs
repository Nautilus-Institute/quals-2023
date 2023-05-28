use std::{
    fmt,
    process,
    process::ExitCode,
    os::fd::AsRawFd,
    io::{stdin, stdout, Write},
    error::Error,
};

use std::io::Error as IoError;
use std::os::unix::net::UnixStream;

use tempfile::NamedTempFile;

extern crate hex;
extern crate libc;

const ENFORCED_PAYLOAD_SIZE: usize = 0x2000;
#[cfg(debug_assertions)]
const SFM_PATH: &str = "./target/debug/sfm";
#[cfg(not(debug_assertions))]
const SFM_PATH: &str = "./sfm";

const LAUNCHER_PATH: &str = "./launcher";

#[derive(Debug)]
enum UpdaterError {
    TooLarge,
    TooSmall
}

impl fmt::Display for UpdaterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpdaterError::TooLarge => write!(f, "Uploaded image too large"),
            UpdaterError::TooSmall => write!(f, "Uploaded image too small")
        }
    }
}

impl Error for UpdaterError {}

fn get_new_image() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut line = String::new();
    
    stdin().read_line(&mut line)?;

    let line = line.trim_end();

    if line.len() > ENFORCED_PAYLOAD_SIZE * 2 {
        return Err(Box::new(UpdaterError::TooLarge));
    }

    let bytes = hex::decode(line)?;
    if bytes.len() != ENFORCED_PAYLOAD_SIZE {
        return Err(Box::new(UpdaterError::TooSmall));
    }

    Ok(bytes)
}

fn do_download(image: &Vec<u8>) -> Result<(), Box<dyn Error>> {
    println!("{}", hex::encode(image));
    stdout().flush()?;

    Ok(())
}

fn launch_sfm() -> Result<(process::Child, UnixStream), Box<dyn Error>> {
    let (client_sock, server_sock) = UnixStream::pair()?;

    // HACK: to remove CLOEXEC
    let duped_fd = unsafe {
        match libc::dup(server_sock.as_raw_fd()) {
            -1 => Err(IoError::last_os_error()),
            new_fd => Ok(new_fd)
        }?
    };

    let child = process::Command::new(SFM_PATH)
                                 .env("FIRMWARE_FD",  duped_fd.as_raw_fd().to_string())
                                 .spawn()
                                 .expect("failed to execute child");

    // server_sock should be closed by going out of scope
    // manually close the duped_fd to prevent it from being inherited in emulator
    unsafe { libc::close(duped_fd) };

    Ok((child, client_sock))
}

fn run_device(image: &Vec<u8>) -> Result<(), Box<dyn Error>> {

    let (mut sfm_child, client_sock) = launch_sfm()?;

    let mut temp_file = NamedTempFile::new()?;
    temp_file.write_all(&image[..])?;

    let temporary_path = temp_file.into_temp_path();

    let duped_fd = unsafe {
        match libc::dup(client_sock.as_raw_fd()) {
            -1 => Err(IoError::last_os_error()),
            new_fd => Ok(new_fd)
        }?
    };

    let mut fw_child = process::Command::new(LAUNCHER_PATH)
                                        .args([&temporary_path])
                                        .env("SFM_FD", duped_fd.as_raw_fd().to_string())
                                        .spawn()
                                        .expect("failed to execute emulator");

    fw_child.wait().expect("emulator wasn't running");

    sfm_child.kill().expect("was not running");

    Ok(())
}

fn io_loop() -> Result<(), Box<dyn Error>> {

    let mut image = include_bytes!("trusted_firmware.raw").to_vec();

    loop {
        let mut line = String::new();

        print!("> ");
        stdout().flush()?;
        stdin().read_line(&mut line)?;

        let command = line.trim();
        if command == String::from("upload") {
            image = get_new_image()?;
        } else if command == String::from("download") {
            do_download(&image)?;
        } else if command == String::from("run") {
            run_device(&image)?;
        } else if command == String::from("quit") {
            break;
        } else {
            println!("Invalid command {:}", command)
        }
    }

    Ok(())
}

fn main() -> ExitCode {
    println!("Welcome to the Ni Smart Lock firmware updater");
    println!("Would you like to download the currently running firmware or update your device?");

    match io_loop() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}
