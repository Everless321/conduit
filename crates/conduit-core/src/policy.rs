use async_trait::async_trait;
use regex::RegexSet;

use crate::models::AuthContext;
use crate::ports::Authorizer;
use crate::{Error, Result};

const DEFAULT_PATTERNS: &[&str] = &[
    r"(?i)\brm\s+(-[a-z]*r[a-z]*f?|-rf|--recursive\s+--force)\s+/(\s|$)",
    r"(?i)\brm\s+(-[a-z]*r[a-z]*f?|-rf)\s+/[a-z]+(\s|$)",
    r"(?i)\bdd\s+[^|;]*of=/dev/(sd|nvme|hd|disk|xvd)",
    r"(?i)\bmkfs(\.|\s)",
    r":\s*\(\s*\)\s*\{\s*:\s*\|",
    r"(?i)\b(shutdown|reboot|halt|poweroff)\b",
    r"(?i)\binit\s+0\b",
    r">\s*/dev/(sd|nvme|hd|disk|xvd)",
    r"(?i)\b(chmod|chown)\s+-R\s+\S+\s+/(\s|$)",
];

/// Default [`Authorizer`]: a regex blacklist of destructive commands plus any
/// operator-supplied extra patterns. Swap in your own `Authorizer` impl for
/// role- or server-aware policies.
#[derive(Clone)]
pub struct CommandPolicy {
    set: RegexSet,
    patterns: Vec<String>,
}

impl CommandPolicy {
    pub fn new(extra: Vec<String>) -> Result<Self> {
        let mut all: Vec<String> = DEFAULT_PATTERNS.iter().map(|s| s.to_string()).collect();
        all.extend(extra);
        let set = RegexSet::new(&all).map_err(|e| Error::Invalid(format!("blacklist regex: {e}")))?;
        Ok(Self { set, patterns: all })
    }

    pub fn check(&self, command: &str) -> Result<()> {
        let m: Vec<usize> = self.set.matches(command).into_iter().collect();
        if let Some(idx) = m.first() {
            return Err(Error::Forbidden(format!(
                "command blocked by policy (pattern #{}: {})",
                idx, self.patterns[*idx]
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl Authorizer for CommandPolicy {
    async fn authorize_exec(
        &self,
        _auth: &AuthContext,
        _server_alias: &str,
        command: &str,
    ) -> Result<()> {
        self.check(command)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_rm_root() {
        let p = CommandPolicy::new(vec![]).unwrap();
        assert!(p.check("rm -rf /").is_err());
        assert!(p.check("rm -rf /etc").is_err());
        assert!(p.check("sudo rm -rf /var").is_err());
    }

    #[test]
    fn allows_safe() {
        let p = CommandPolicy::new(vec![]).unwrap();
        assert!(p.check("ls -la").is_ok());
        assert!(p.check("ps aux | grep nginx").is_ok());
        assert!(p.check("rm /tmp/file.txt").is_ok());
        assert!(p.check("rm -rf /tmp/build").is_ok());
    }

    #[test]
    fn blocks_dd_disk() {
        let p = CommandPolicy::new(vec![]).unwrap();
        assert!(p.check("dd if=/dev/zero of=/dev/sda").is_err());
    }

    #[test]
    fn blocks_fork_bomb() {
        let p = CommandPolicy::new(vec![]).unwrap();
        assert!(p.check(":(){ :|:& };:").is_err());
    }

    #[test]
    fn custom_pattern() {
        let p = CommandPolicy::new(vec![r"(?i)\bcurl\b.*\|\s*sh\b".into()]).unwrap();
        assert!(p.check("curl https://x | sh").is_err());
    }
}
