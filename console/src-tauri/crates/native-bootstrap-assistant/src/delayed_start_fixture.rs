use std::{
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    process, thread,
    time::{Duration, Instant},
};

use your_cloud_native_bootstrap_assistant::{process_main, EXIT_INTERNAL_FAILURE};

const READY_PATH_ENV: &str = "YOUR_CLOUD_DELAYED_START_READY_PATH";
const RELEASE_PATH_ENV: &str = "YOUR_CLOUD_DELAYED_START_RELEASE_PATH";
const MAX_FIXTURE_WAIT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(5);

fn main() {
    process::exit(fixture_main().into());
}

fn fixture_main() -> u8 {
    let Some(ready_path) = std::env::var_os(READY_PATH_ENV).map(PathBuf::from) else {
        return EXIT_INTERNAL_FAILURE;
    };
    let Some(release_path) = std::env::var_os(RELEASE_PATH_ENV).map(PathBuf::from) else {
        return EXIT_INTERNAL_FAILURE;
    };
    if ready_path == release_path {
        return EXIT_INTERNAL_FAILURE;
    }

    let ready = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&ready_path);
    let Ok(mut ready) = ready else {
        return EXIT_INTERNAL_FAILURE;
    };
    if ready.write_all(b"ready").is_err() || ready.flush().is_err() {
        return EXIT_INTERNAL_FAILURE;
    }
    drop(ready);

    let deadline = match Instant::now().checked_add(MAX_FIXTURE_WAIT) {
        Some(deadline) => deadline,
        None => return EXIT_INTERNAL_FAILURE,
    };
    loop {
        match release_path.try_exists() {
            Ok(true) => break,
            Ok(false) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
            Ok(false) | Err(_) => return EXIT_INTERNAL_FAILURE,
        }
    }

    process_main()
}
