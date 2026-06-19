use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

pub struct RateLimiter {
    per_minute: u32,
    state: Mutex<HashMap<i64, VecDeque<Instant>>>,
}

impl RateLimiter {
    pub fn new(per_minute: u32) -> Self {
        Self { per_minute, state: Mutex::new(HashMap::new()) }
    }

    pub fn check_and_record(&self, token_id: i64) -> Result<(), String> {
        if self.per_minute == 0 {
            return Ok(());
        }
        let mut state = self.state.lock();
        let entry = state.entry(token_id).or_default();
        let cutoff = Instant::now() - Duration::from_secs(60);
        while let Some(front) = entry.front() {
            if *front < cutoff { entry.pop_front(); } else { break; }
        }
        if (entry.len() as u32) >= self.per_minute {
            return Err(format!("rate limit exceeded: {}/min", self.per_minute));
        }
        entry.push_back(Instant::now());
        Ok(())
    }
}
