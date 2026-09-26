//! Verifier failure retry semantics for Harpocrates (#326).
//!
//! This module is the single protocol authority for whether a verifier-path
//! failure is safe to retry. It is deliberately `no_std`, allocation-free, and
//! independent of the Soroban SDK so the same tables can be mirrored by
//! backend and browser clients without inventing a second truth.
//!
//! # Trust boundary
//!
//! - On-chain, the registry invokes an external UltraHonk verifier via
//!   `try_invoke_contract`. Cryptographic rejection and callee traps are
//!   **permanent** for the supplied proof material.
//! - Transient dependency failures (missing/unconfigured verifier host edge
//!   cases) may be retried **in-transaction** up to
//!   [`MAX_VERIFIER_INVOKE_ATTEMPTS`], then surface a stable error so an
//!   operator can remediate and a client can retry later.
//! - Callers must never log real media, secrets, witness values, proof blobs,
//!   or private keys when recording a failure class.
//!
//! # Compatibility
//!
//! Additive only: existing `RegistryError` discriminants are unchanged. New
//! codes are appended. Pre-#326 deployments that ignore the new view helpers
//! keep working; rolling back the wasm simply drops the helpers and the
//! in-tx retry loop.

/// Protocol identifier for this retry table (signals / docs).
pub const RETRY_SEMANTICS_ID: &str = "hpx-vr/1";

/// Maximum in-transaction invoke attempts for retryable dependency failures.
/// Permanent proof rejects never consume more than one attempt.
pub const MAX_VERIFIER_INVOKE_ATTEMPTS: u32 = 3;

/// Stable failure classes. Discriminants are append-only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum VerifierFailureClass {
    /// Public inputs / proof framing failed codec checks (malformed, length,
    /// padding, non-canonical, domain mismatch, undersize/oversize).
    Malformed = 1,
    /// Proof blob exceeded the accepted size window.
    Oversized = 2,
    /// Credential root or proof TTL has expired.
    Expired = 3,
    /// Credential root (or related attestation) was revoked.
    Revoked = 4,
    /// Schema / circuit / domain is unknown or inactive.
    Unsupported = 5,
    /// External verifier cryptographically rejected the proof, or trapped.
    PermanentReject = 6,
    /// Verifier dependency is missing, misconfigured, or temporarily
    /// unreachable. Safe for a bounded client retry after remediation.
    DependencyFailure = 7,
    /// In-tx retry budget for a dependency failure was exhausted.
    RetryExhausted = 8,
}

impl VerifierFailureClass {
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::Oversized => "oversized",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Unsupported => "unsupported",
            Self::PermanentReject => "permanent_reject",
            Self::DependencyFailure => "dependency_failure",
            Self::RetryExhausted => "retry_exhausted",
        }
    }

    /// Whether a *client* may retry the same logical registration after this
    /// class of failure (possibly after waiting for operator remediation).
    pub const fn client_retryable(self) -> bool {
        match self {
            Self::DependencyFailure | Self::RetryExhausted => true,
            Self::Malformed
            | Self::Oversized
            | Self::Expired
            | Self::Revoked
            | Self::Unsupported
            | Self::PermanentReject => false,
        }
    }

    /// Whether the registry may re-invoke the verifier inside the same
    /// transaction for this class.
    pub const fn in_tx_retryable(self) -> bool {
        matches!(self, Self::DependencyFailure)
    }
}

/// Map a stable `RegistryError` discriminant onto a failure class.
///
/// Unknown / future codes are treated as non-retryable so an outdated client
/// fails closed rather than hammering the network.
pub const fn classify_registry_error(code: u32) -> VerifierFailureClass {
    match code {
        // InvalidPublicInputs
        10 => VerifierFailureClass::Malformed,
        // AlreadyExpired
        17 => VerifierFailureClass::Expired,
        // RevokedCredentialRoot
        12 => VerifierFailureClass::Revoked,
        // UnknownSchema / InactiveSchema / SchemaVersionMismatch / DomainTagMismatch
        49 | 50 | 51 | 52 => VerifierFailureClass::Unsupported,
        // InvalidProof
        7 => VerifierFailureClass::PermanentReject,
        // VerifierNotSet / VerifierDependencyFailure
        9 | 68 => VerifierFailureClass::DependencyFailure,
        // VerifierRetryExhausted
        69 => VerifierFailureClass::RetryExhausted,
        _ => VerifierFailureClass::PermanentReject,
    }
}

/// Map a `RejectCode::as_code` value from the verifier-input codec.
pub const fn classify_reject_code(code: u32) -> VerifierFailureClass {
    match code {
        // ProofOversize
        8 => VerifierFailureClass::Oversized,
        // UnknownSchema
        9 => VerifierFailureClass::Unsupported,
        // MalformedHex, Length, Padding, NonCanonicalField, ZeroField,
        // DomainMismatch, ProofUndersize
        1 | 2 | 3 | 4 | 5 | 6 | 7 => VerifierFailureClass::Malformed,
        _ => VerifierFailureClass::Malformed,
    }
}

/// Outcome of a single external verifier invoke attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifierInvokeOutcome {
    Accepted,
    PermanentReject,
    DependencyFailure,
}

/// Classify a `try_invoke_contract` result for `verify_proof`.
///
/// - `accepted`: callee returned successfully.
/// - `permanent_reject`: callee aborted or returned a contract error (proof
///   material is not valid under the configured VK).
/// - `dependency_failure`: host-level invoke failure that is not a clean
///   cryptographic reject. Callers may retry in-tx up to the attempt cap.
///
/// The boolean flags mirror the existing match shape used by the registry:
/// `(outer_ok, inner_ok)`.
pub const fn classify_invoke_flags(outer_ok: bool, inner_ok: bool) -> VerifierInvokeOutcome {
    if outer_ok && inner_ok {
        VerifierInvokeOutcome::Accepted
    } else if outer_ok && !inner_ok {
        // Typed contract error from the verifier — treat as permanent reject.
        VerifierInvokeOutcome::PermanentReject
    } else {
        // Outer Err(InvokeError::Abort) is the common path for a rejecting
        // mock / UltraHonk verifier trap → permanent.
        // Genuine host dependency faults are indistinguishable from Abort in
        // current Soroban InvokeError surface, so callers that need a
        // dependency class should use `classify_invoke_error_code`.
        VerifierInvokeOutcome::PermanentReject
    }
}

/// Refine an outer `InvokeError` discriminant when available.
///
/// Soroban `InvokeError`: `Abort = 1`, `Contract(code)` carries the contract
/// error. Both are permanent rejects for proof verification. A zero / unknown
/// code is classified as dependency failure so operators can remediate.
pub const fn classify_invoke_error_code(has_outer_error: bool, abort: bool, contract_code: u32) -> VerifierInvokeOutcome {
    if !has_outer_error {
        return VerifierInvokeOutcome::Accepted;
    }
    if abort || contract_code != 0 {
        VerifierInvokeOutcome::PermanentReject
    } else {
        VerifierInvokeOutcome::DependencyFailure
    }
}

/// Decide whether another in-tx attempt is permitted.
pub const fn should_retry_in_tx(outcome: VerifierInvokeOutcome, attempt: u32) -> bool {
    matches!(outcome, VerifierInvokeOutcome::DependencyFailure)
        && attempt < MAX_VERIFIER_INVOKE_ATTEMPTS
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn permanent_classes_are_not_client_retryable() {
        for class in [
            VerifierFailureClass::Malformed,
            VerifierFailureClass::Oversized,
            VerifierFailureClass::Expired,
            VerifierFailureClass::Revoked,
            VerifierFailureClass::Unsupported,
            VerifierFailureClass::PermanentReject,
        ] {
            assert!(!class.client_retryable());
            assert!(!class.in_tx_retryable());
        }
    }

    #[test]
    fn dependency_classes_are_client_retryable() {
        assert!(VerifierFailureClass::DependencyFailure.client_retryable());
        assert!(VerifierFailureClass::DependencyFailure.in_tx_retryable());
        assert!(VerifierFailureClass::RetryExhausted.client_retryable());
        assert!(!VerifierFailureClass::RetryExhausted.in_tx_retryable());
    }

    #[test]
    fn registry_error_mapping_is_stable() {
        assert_eq!(classify_registry_error(7), VerifierFailureClass::PermanentReject);
        assert_eq!(classify_registry_error(10), VerifierFailureClass::Malformed);
        assert_eq!(classify_registry_error(12), VerifierFailureClass::Revoked);
        assert_eq!(classify_registry_error(17), VerifierFailureClass::Expired);
        assert_eq!(classify_registry_error(50), VerifierFailureClass::Unsupported);
        assert_eq!(classify_registry_error(9), VerifierFailureClass::DependencyFailure);
        assert_eq!(classify_registry_error(68), VerifierFailureClass::DependencyFailure);
        assert_eq!(classify_registry_error(69), VerifierFailureClass::RetryExhausted);
        // Unknown codes fail closed.
        assert_eq!(classify_registry_error(999), VerifierFailureClass::PermanentReject);
        assert!(!classify_registry_error(999).client_retryable());
    }

    #[test]
    fn reject_code_mapping_covers_oversize_and_schema() {
        assert_eq!(classify_reject_code(8), VerifierFailureClass::Oversized);
        assert_eq!(classify_reject_code(9), VerifierFailureClass::Unsupported);
        assert_eq!(classify_reject_code(2), VerifierFailureClass::Malformed);
    }

    #[test]
    fn invoke_flags_classify_accept_and_reject() {
        assert_eq!(
            classify_invoke_flags(true, true),
            VerifierInvokeOutcome::Accepted
        );
        assert_eq!(
            classify_invoke_flags(true, false),
            VerifierInvokeOutcome::PermanentReject
        );
        assert_eq!(
            classify_invoke_flags(false, false),
            VerifierInvokeOutcome::PermanentReject
        );
    }

    #[test]
    fn in_tx_retry_budget() {
        assert!(should_retry_in_tx(
            VerifierInvokeOutcome::DependencyFailure,
            1
        ));
        assert!(should_retry_in_tx(
            VerifierInvokeOutcome::DependencyFailure,
            2
        ));
        assert!(!should_retry_in_tx(
            VerifierInvokeOutcome::DependencyFailure,
            3
        ));
        assert!(!should_retry_in_tx(
            VerifierInvokeOutcome::PermanentReject,
            1
        ));
    }
}
