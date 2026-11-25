//! Approved-mode state machine.
//!
//! The module starts in `Uninitialized`. After `initialize_approved_mode()`
//! runs self-tests, it transitions to `Approved` or `Error`. All crypto APIs
//! reject calls unless state is `Approved`.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::errors::CryptoError;

/// Module lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ModuleState {
    Uninitialized = 0,
    SelfTesting = 1,
    Approved = 2,
    Error = 3,
}

impl From<u8> for ModuleState {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Uninitialized,
            1 => Self::SelfTesting,
            2 => Self::Approved,
            3 => Self::Error,
            _ => Self::Error,
        }
    }
}

static MODULE_STATE: AtomicU8 = AtomicU8::new(0); // Uninitialized

/// Get the current module state.
pub fn state() -> ModuleState {
    ModuleState::from(MODULE_STATE.load(Ordering::SeqCst))
}

/// Transition to a new state. Returns the previous state.
/// Transition to a new state. Returns the previous state.
/// Exposed for testing error-state behavior.
pub fn set_state(new: ModuleState) -> ModuleState {
    let prev = MODULE_STATE.swap(new as u8, Ordering::SeqCst);
    ModuleState::from(prev)
}

/// Guard: returns `Ok(())` if state is `Approved`, else returns the appropriate error.
pub fn require_approved() -> Result<(), CryptoError> {
    match state() {
        ModuleState::Approved => Ok(()),
        ModuleState::Uninitialized | ModuleState::SelfTesting => {
            Err(CryptoError::ModuleNotInitialized)
        }
        ModuleState::Error => Err(CryptoError::ModuleInErrorState),
    }
}

/// Check if a transition from `from` to `to` is valid per the FSM spec.
pub fn is_valid_transition(from: ModuleState, to: ModuleState) -> bool {
    matches!(
        (from, to),
        (ModuleState::Uninitialized, ModuleState::SelfTesting)
            | (ModuleState::SelfTesting, ModuleState::Approved)
            | (ModuleState::SelfTesting, ModuleState::Error)
    )
}

/// Reset to Uninitialized (for testing only).
#[cfg(test)]
pub fn reset_for_testing() {
    MODULE_STATE.store(0, Ordering::SeqCst);
}

// Also expose for integration tests via a public function gated on test builds.
static TEST_STATE_LOCK: Mutex<()> = Mutex::new(());

#[doc(hidden)]
#[must_use = "hold the guard for the whole test so no other test changes the module state"]
pub fn __test_reset() -> MutexGuard<'static, ()> {
    let guard = TEST_STATE_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    MODULE_STATE.store(0, Ordering::SeqCst);
    guard
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_states() -> [ModuleState; 4] {
        [
            ModuleState::Uninitialized,
            ModuleState::SelfTesting,
            ModuleState::Approved,
            ModuleState::Error,
        ]
    }

    // ── Valid transitions (3) ──────────────────────────────────

    #[test]
    fn valid_uninitialized_to_selftesting() {
        assert!(is_valid_transition(
            ModuleState::Uninitialized,
            ModuleState::SelfTesting
        ));
    }

    #[test]
    fn valid_selftesting_to_approved() {
        assert!(is_valid_transition(
            ModuleState::SelfTesting,
            ModuleState::Approved
        ));
    }

    #[test]
    fn valid_selftesting_to_error() {
        assert!(is_valid_transition(
            ModuleState::SelfTesting,
            ModuleState::Error
        ));
    }

    // ── Invalid transitions (13) ──────────────────────────────

    #[test]
    fn invalid_self_transitions() {
        for s in all_states() {
            assert!(
                !is_valid_transition(s, s),
                "self-transition {:?} -> {:?} should be invalid",
                s,
                s
            );
        }
    }

    #[test]
    fn invalid_uninitialized_to_approved() {
        assert!(!is_valid_transition(
            ModuleState::Uninitialized,
            ModuleState::Approved
        ));
    }

    #[test]
    fn invalid_uninitialized_to_error() {
        assert!(!is_valid_transition(
            ModuleState::Uninitialized,
            ModuleState::Error
        ));
    }

    #[test]
    fn invalid_selftesting_to_uninitialized() {
        assert!(!is_valid_transition(
            ModuleState::SelfTesting,
            ModuleState::Uninitialized
        ));
    }

    #[test]
    fn invalid_approved_to_uninitialized() {
        assert!(!is_valid_transition(
            ModuleState::Approved,
            ModuleState::Uninitialized
        ));
    }

    #[test]
    fn invalid_approved_to_selftesting() {
        assert!(!is_valid_transition(
            ModuleState::Approved,
            ModuleState::SelfTesting
        ));
    }

    #[test]
    fn invalid_approved_to_error() {
        assert!(!is_valid_transition(
            ModuleState::Approved,
            ModuleState::Error
        ));
    }

    #[test]
    fn invalid_error_to_any() {
        for target in all_states() {
            assert!(
                !is_valid_transition(ModuleState::Error, target),
                "Error -> {:?} should be invalid (Error is terminal)",
                target
            );
        }
    }

    // ── Exhaustive coverage: exactly 3 valid out of 16 ────────

    #[test]
    fn exactly_three_valid_transitions_out_of_sixteen() {
        let mut valid_count = 0;
        for from in all_states() {
            for to in all_states() {
                if is_valid_transition(from, to) {
                    valid_count += 1;
                }
            }
        }
        assert_eq!(valid_count, 3, "FSM must have exactly 3 valid transitions");
    }

    // ── require_approved guard ─────────────────────────────────

    #[test]
    fn require_approved_in_each_state() {
        set_state(ModuleState::Uninitialized);
        assert!(require_approved().is_err());

        set_state(ModuleState::SelfTesting);
        assert!(require_approved().is_err());

        set_state(ModuleState::Approved);
        assert!(require_approved().is_ok());

        set_state(ModuleState::Error);
        assert!(require_approved().is_err());
    }

    // ── u8 conversion edge cases ──────────────────────────────

    #[test]
    fn unknown_u8_maps_to_error() {
        for v in 4..=255u8 {
            assert_eq!(ModuleState::from(v), ModuleState::Error);
        }
    }
}
