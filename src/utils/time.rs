use web_time::{Duration, SystemTime, UNIX_EPOCH};

pub fn current_epoch() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
}

pub fn current_epoch_secs() -> usize {
    current_epoch().as_secs() as usize
}
