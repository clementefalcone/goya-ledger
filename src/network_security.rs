/**
 * Network Security Layer
 *
 * Implements protection against network-level attacks:
 * - Peer scoring and reputation system
 * - Rate limiting per peer
 * - Connection limits
 * - Message validation and size limits
 * - Peer blacklisting
 */
use std::collections::HashMap;
use std::time::SystemTime;

/**
 * Peer reputation and scoring system
 */
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PeerScore {
    pub address: String,
    pub score: i32,
    pub last_seen: u64,
    pub messages_received: u64,
    pub messages_rejected: u64,
    pub bytes_received: u64,
    pub is_blacklisted: bool,
    pub blacklist_reason: Option<String>,
    pub banned_at: Option<u64>,
}

#[allow(dead_code)]
impl PeerScore {
    pub fn new(address: String) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        PeerScore {
            address,
            score: 100,
            last_seen: now,
            messages_received: 0,
            messages_rejected: 0,
            bytes_received: 0,
            is_blacklisted: false,
            blacklist_reason: None,
            banned_at: None,
        }
    }

    pub fn is_trusted(&self) -> bool {
        !self.is_blacklisted && self.score > 50
    }

    pub fn is_suspect(&self) -> bool {
        self.score < 50 && self.score >= 0
    }

    pub fn is_banned(&self) -> bool {
        self.score < 0 || self.is_blacklisted
    }

    fn stamp_ban_time(&mut self) {
        if self.is_banned() && self.banned_at.is_none() {
            self.banned_at = Some(unix_now());
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/**
 * Rate limiting configuration and tracking
 */
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RateLimitConfig {
    pub max_messages_per_second: u32,
    pub max_bytes_per_second: u64,
    pub max_concurrent_connections: usize,
    pub message_size_limit: usize,
    pub ban_threshold_score: i32,
    pub suspect_threshold_score: i32,
    pub ban_duration_seconds: u64,
    pub max_connections_per_peer: usize,
    pub max_connections_per_validator: usize,
    pub max_state_requests_per_second: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitConfig {
            max_messages_per_second: 100,
            max_bytes_per_second: 10_000_000, // 10MB/s
            max_concurrent_connections: 256,
            message_size_limit: 10_000_000, // 10MB max message
            ban_threshold_score: -50,
            suspect_threshold_score: 50,
            ban_duration_seconds: 600,
            max_connections_per_peer: 16,
            max_connections_per_validator: 64,
            max_state_requests_per_second: 5,
        }
    }
}

/**
 * Rate limiting state for a single peer
 */
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PeerRateLimit {
    pub address: String,
    pub messages_this_second: u32,
    pub state_requests_this_second: u32,
    pub bytes_this_second: u64,
    pub last_reset: u64,
}

impl PeerRateLimit {
    pub fn new(address: String) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        PeerRateLimit {
            address,
            messages_this_second: 0,
            state_requests_this_second: 0,
            bytes_this_second: 0,
            last_reset: now,
        }
    }

    pub fn reset_if_needed(&mut self) {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now > self.last_reset {
            self.messages_this_second = 0;
            self.state_requests_this_second = 0;
            self.bytes_this_second = 0;
            self.last_reset = now;
        }
    }
}

/**
 * Network security manager
 */
pub struct NetworkSecurityManager {
    pub config: RateLimitConfig,
    pub peer_scores: HashMap<String, PeerScore>,
    pub rate_limits: HashMap<String, PeerRateLimit>,
    pub active_connections: usize,
    pub connections_by_peer: HashMap<String, usize>,
}

impl NetworkSecurityManager {
    pub fn new(config: RateLimitConfig) -> Self {
        NetworkSecurityManager {
            config,
            peer_scores: HashMap::new(),
            rate_limits: HashMap::new(),
            active_connections: 0,
            connections_by_peer: HashMap::new(),
        }
    }

    pub fn with_defaults() -> Self {
        NetworkSecurityManager::new(RateLimitConfig::default())
    }

    /**
     * Register a new peer connection
     */
    pub fn register_peer(&mut self, address: String) -> Result<(), String> {
        if self.active_connections >= self.config.max_concurrent_connections {
            return Err("Max concurrent connections reached".to_string());
        }
        self.register_with_cap(address, self.config.max_connections_per_peer)?;
        self.active_connections += 1;
        Ok(())
    }

    pub fn register_validator(&mut self, address: String) -> Result<(), String> {
        self.register_with_cap(address, self.config.max_connections_per_validator)
    }

    fn register_with_cap(&mut self, address: String, cap: usize) -> Result<(), String> {
        self.lift_expired_ban(&address);
        if self
            .peer_scores
            .get(&address)
            .is_some_and(|s| s.is_banned())
        {
            return Err(format!("Peer {address} is banned"));
        }

        let peer_connections = self.connections_by_peer.entry(address.clone()).or_insert(0);
        if *peer_connections >= cap {
            return Err(format!("Peer {address} already holds {cap} connections"));
        }
        *peer_connections += 1;

        if !self.peer_scores.contains_key(&address) {
            self.peer_scores
                .insert(address.clone(), PeerScore::new(address.clone()));
            self.rate_limits
                .insert(address.clone(), PeerRateLimit::new(address));
        }
        Ok(())
    }

    fn lift_expired_ban(&mut self, address: &str) {
        let ban_ends_at = self
            .peer_scores
            .get(address)
            .and_then(|s| s.banned_at)
            .map(|banned_at| banned_at + self.config.ban_duration_seconds);
        if ban_ends_at.is_some_and(|ends_at| unix_now() >= ends_at) {
            self.peer_scores.remove(address);
            self.rate_limits.remove(address);
        }
    }

    /**
     * Unregister a peer connection
     */
    pub fn unregister_peer(&mut self, address: &str) {
        self.active_connections = self.active_connections.saturating_sub(1);
        self.release_connection(address);
    }

    pub fn unregister_validator(&mut self, address: &str) {
        self.release_connection(address);
    }

    fn release_connection(&mut self, address: &str) {
        if let Some(count) = self.connections_by_peer.get_mut(address) {
            *count -= 1;
            if *count == 0 {
                self.connections_by_peer.remove(address);
            }
        }
    }

    /**
     * Validate incoming message size
     */
    pub fn validate_message_size(&self, size: usize) -> Result<(), String> {
        if size > self.config.message_size_limit {
            return Err(format!(
                "Message size {} exceeds limit {}",
                size, self.config.message_size_limit
            ));
        }
        Ok(())
    }

    /**
     * Check if peer can send message (rate limiting)
     */
    pub fn check_rate_limit(&mut self, address: &str, message_size: usize) -> Result<(), String> {
        // Validate message size first
        self.validate_message_size(message_size)?;

        let peer_score = self.peer_scores.get(address);
        if peer_score.is_none() {
            return Err("Peer not registered".to_string());
        }

        let peer_score = peer_score.unwrap();

        // Check if peer is banned
        if peer_score.is_banned() {
            return Err(format!(
                "Peer is banned. Score: {}. Reason: {:?}",
                peer_score.score, peer_score.blacklist_reason
            ));
        }

        // Get or create rate limit entry
        let rate_limit = self
            .rate_limits
            .entry(address.to_string())
            .or_insert_with(|| PeerRateLimit::new(address.to_string()));

        // Reset if needed
        rate_limit.reset_if_needed();

        // Check byte rate
        if rate_limit.bytes_this_second + message_size as u64 > self.config.max_bytes_per_second {
            self.penalize_peer(address, 5, Some("Rate limit exceeded: bytes".to_string()));
            return Err("Rate limit exceeded: too many bytes".to_string());
        }

        // Update tracking
        rate_limit.bytes_this_second += message_size as u64;

        Ok(())
    }

    pub fn check_message_rate(&mut self, address: &str) -> Result<(), String> {
        let rate_limit = self
            .rate_limits
            .entry(address.to_string())
            .or_insert_with(|| PeerRateLimit::new(address.to_string()));
        rate_limit.reset_if_needed();
        if rate_limit.messages_this_second >= self.config.max_messages_per_second {
            self.penalize_peer(
                address,
                5,
                Some("Rate limit exceeded: messages".to_string()),
            );
            return Err("Rate limit exceeded: too many messages".to_string());
        }
        rate_limit.messages_this_second += 1;
        Ok(())
    }

    pub fn check_state_request(&mut self, address: &str) -> Result<(), String> {
        let rate_limit = self
            .rate_limits
            .entry(address.to_string())
            .or_insert_with(|| PeerRateLimit::new(address.to_string()));
        rate_limit.reset_if_needed();
        if rate_limit.state_requests_this_second >= self.config.max_state_requests_per_second {
            return Err(format!(
                "{address} exceeded {} state requests per second",
                self.config.max_state_requests_per_second
            ));
        }
        rate_limit.state_requests_this_second += 1;
        Ok(())
    }

    /**
     * Record successful message from peer (rewards good behavior)
     */
    pub fn record_valid_message(&mut self, address: &str, _message_size: usize) {
        if let Some(score) = self.peer_scores.get_mut(address) {
            score.messages_received += 1;
            score.last_seen = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            // Reward good behavior - increase score up to 150 max
            score.score = (score.score + 5).min(150);
        }
    }

    /**
     * Record rejected/invalid message from peer (penalizes bad behavior)
     */
    #[allow(dead_code)]
    pub fn record_invalid_message(&mut self, address: &str, penalty: i32) {
        if let Some(score) = self.peer_scores.get_mut(address) {
            score.messages_rejected += 1;
            score.score -= penalty;
            score.last_seen = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // Auto-blacklist if score too low
            if score.score <= self.config.ban_threshold_score {
                score.is_blacklisted = true;
                score.blacklist_reason = Some(format!("Score dropped to {}", score.score));
            }
            score.stamp_ban_time();
        }
    }

    /**
     * Manually penalize a peer
     */
    pub fn penalize_peer(&mut self, address: &str, penalty: i32, reason: Option<String>) {
        if let Some(score) = self.peer_scores.get_mut(address) {
            score.score -= penalty;
            if reason.is_some() {
                score.blacklist_reason = reason;
            }

            if score.score <= self.config.ban_threshold_score {
                score.is_blacklisted = true;
            }
            score.stamp_ban_time();
        }
    }

    /**
     * Blacklist a peer permanently
     */
    #[allow(dead_code)]
    pub fn blacklist_peer(&mut self, address: &str, reason: String) {
        if let Some(score) = self.peer_scores.get_mut(address) {
            score.is_blacklisted = true;
            score.blacklist_reason = Some(reason);
            score.score = self.config.ban_threshold_score - 100;
            score.stamp_ban_time();
        }
    }

    /**
     * Get peer statistics
     */
    #[allow(dead_code)]
    pub fn get_peer_stats(&self, address: &str) -> Option<PeerStatistics> {
        self.peer_scores.get(address).map(|score| PeerStatistics {
            address: score.address.clone(),
            score: score.score,
            messages_received: score.messages_received,
            messages_rejected: score.messages_rejected,
            status: if score.is_banned() {
                "BANNED".to_string()
            } else if score.is_suspect() {
                "SUSPECT".to_string()
            } else {
                "TRUSTED".to_string()
            },
        })
    }

    /**
     * Get all peer statistics
     */
    #[allow(dead_code)]
    pub fn get_all_peer_stats(&self) -> Vec<PeerStatistics> {
        self.peer_scores
            .values()
            .map(|score| PeerStatistics {
                address: score.address.clone(),
                score: score.score,
                messages_received: score.messages_received,
                messages_rejected: score.messages_rejected,
                status: if score.is_banned() {
                    "BANNED".to_string()
                } else if score.is_suspect() {
                    "SUSPECT".to_string()
                } else {
                    "TRUSTED".to_string()
                },
            })
            .collect()
    }

    /**
     * Cleanup old connections
     */
    #[allow(dead_code)]
    pub fn cleanup_inactive_peers(&mut self, max_inactive_seconds: u64) {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.peer_scores.retain(|_, score| {
            now - score.last_seen < max_inactive_seconds || score.is_blacklisted
        });

        self.rate_limits
            .retain(|address, _| self.peer_scores.contains_key(address));
    }
}

/**
 * Peer statistics for reporting
 */
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PeerStatistics {
    pub address: String,
    pub score: i32,
    pub messages_received: u64,
    pub messages_rejected: u64,
    pub status: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_registration() {
        let mut manager = NetworkSecurityManager::with_defaults();
        let result = manager.register_peer("127.0.0.1:8081".to_string());
        assert!(result.is_ok());
        assert_eq!(manager.active_connections, 1);
    }

    #[test]
    fn test_rate_limiting() {
        let mut manager = NetworkSecurityManager::with_defaults();
        manager.register_peer("127.0.0.1:8081".to_string()).unwrap();

        // First message should succeed
        let result = manager.check_rate_limit("127.0.0.1:8081", 1000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_message_size_validation() {
        let manager = NetworkSecurityManager::with_defaults();
        let result = manager.validate_message_size(100_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_peer_scoring() {
        let mut manager = NetworkSecurityManager::with_defaults();
        manager.register_peer("127.0.0.1:8081".to_string()).unwrap();

        manager.record_valid_message("127.0.0.1:8081", 1000);
        let stats = manager.get_peer_stats("127.0.0.1:8081").unwrap();
        assert!(stats.score > 100);

        manager.penalize_peer("127.0.0.1:8081", 30, None);
        let stats = manager.get_peer_stats("127.0.0.1:8081").unwrap();
        assert!(stats.score < 100);
    }

    #[test]
    fn test_peer_blacklisting() {
        let mut manager = NetworkSecurityManager::with_defaults();
        manager.register_peer("127.0.0.1:8081".to_string()).unwrap();

        manager.blacklist_peer("127.0.0.1:8081", "Test ban".to_string());
        let result = manager.check_rate_limit("127.0.0.1:8081", 1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_connection_limit() {
        let mut manager = NetworkSecurityManager::with_defaults();
        manager.config.max_concurrent_connections = 2;

        manager.register_peer("127.0.0.1:8081".to_string()).unwrap();
        manager.register_peer("127.0.0.1:8082".to_string()).unwrap();

        let result = manager.register_peer("127.0.0.1:8083".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn banned_peer_cannot_reconnect_until_the_ban_expires() {
        let mut manager = NetworkSecurityManager::with_defaults();
        manager.register_peer("10.0.0.7".to_string()).unwrap();
        manager.blacklist_peer("10.0.0.7", "invalid messages".to_string());

        assert!(manager.register_peer("10.0.0.7".to_string()).is_err());

        let ban_length = manager.config.ban_duration_seconds;
        if let Some(score) = manager.peer_scores.get_mut("10.0.0.7") {
            score.banned_at = Some(unix_now() - ban_length);
        }

        assert!(manager.register_peer("10.0.0.7".to_string()).is_ok());
        assert!(manager.check_rate_limit("10.0.0.7", 1000).is_ok());
    }

    #[test]
    fn one_peer_cannot_take_every_connection_slot() {
        let mut manager = NetworkSecurityManager::with_defaults();
        let cap = manager.config.max_connections_per_peer;
        for _ in 0..cap {
            manager.register_peer("10.0.0.9".to_string()).unwrap();
        }

        assert!(manager.register_peer("10.0.0.9".to_string()).is_err());
        assert!(manager.register_peer("10.0.0.10".to_string()).is_ok());
        manager.unregister_peer("10.0.0.9");
        assert!(manager.register_peer("10.0.0.9".to_string()).is_ok());
    }

    #[test]
    fn validators_get_room_for_bursts_that_strangers_do_not() {
        let mut manager = NetworkSecurityManager::with_defaults();
        for _ in 0..manager.config.max_connections_per_peer {
            manager.register_peer("10.0.0.11".to_string()).unwrap();
        }

        assert!(manager.register_peer("10.0.0.11".to_string()).is_err());
        assert!(manager.register_validator("10.0.0.11".to_string()).is_ok());
    }

    #[test]
    fn strangers_filling_every_slot_do_not_lock_out_validators() {
        let mut manager = NetworkSecurityManager::with_defaults();
        manager.config.max_concurrent_connections = 2;
        manager.register_peer("10.0.0.21".to_string()).unwrap();
        manager.register_peer("10.0.0.22".to_string()).unwrap();

        assert!(manager.register_peer("10.0.0.23".to_string()).is_err());
        assert!(manager.register_validator("10.0.0.30".to_string()).is_ok());
        manager.unregister_validator("10.0.0.30");
        assert_eq!(manager.active_connections, 2);
        manager.unregister_peer("10.0.0.21");
        assert!(manager.register_peer("10.0.0.23".to_string()).is_ok());
    }

    #[test]
    fn message_rate_counts_messages_not_reads() {
        let mut manager = NetworkSecurityManager::with_defaults();
        manager.register_peer("10.0.0.8".to_string()).unwrap();
        if let Some(window) = manager.rate_limits.get_mut("10.0.0.8") {
            window.last_reset = u64::MAX;
        }
        let limit = manager.config.max_messages_per_second;

        for _ in 0..limit * 3 {
            assert!(manager.check_rate_limit("10.0.0.8", 1000).is_ok());
        }
        for _ in 0..limit {
            assert!(manager.check_message_rate("10.0.0.8").is_ok());
        }

        assert!(manager.check_message_rate("10.0.0.8").is_err());
    }

    #[test]
    fn state_requests_from_one_validator_are_capped_per_second() {
        let mut manager = NetworkSecurityManager::with_defaults();
        manager.register_validator("10.0.0.40".to_string()).unwrap();
        manager.register_validator("10.0.0.41".to_string()).unwrap();
        manager
            .rate_limits
            .values_mut()
            .for_each(|window| window.last_reset = u64::MAX);
        let limit = manager.config.max_state_requests_per_second;

        for _ in 0..limit {
            assert!(manager.check_state_request("10.0.0.40").is_ok());
        }

        assert!(manager.check_state_request("10.0.0.40").is_err());
        assert!(manager.check_state_request("10.0.0.41").is_ok());
        assert_eq!(manager.peer_scores["10.0.0.40"].score, 100);
    }
}
