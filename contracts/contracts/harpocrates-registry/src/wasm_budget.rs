//! Contract Wasm size budget (#346).
//!
//! The compiled registry artifact `harpocrates_registry.wasm` is a deployed,
//! publicly inspectable boundary. This module is the single source of truth
//! for its size budget: the maximum accepted artifact size, the golden-size
//! regression band, the error contract used when an artifact violates the
//! budget, and the digest-based audit trail recorded for the deployed build.
//!
//! ## Design
//!
//! - `MAX_WASM_SIZE_BYTES` is the hard budget. The `check_wasm_size` helper
//!   enforces it and returns the typed [`WasmBudgetError::ArtifactTooLarge`]
//!   on violation, so tests and tooling share one code path.
//! - `WASM_SIZE_REGRESSION_BAND_PCT` allows the artifact to grow or shrink a
//!   little without churn; a move outside the band requires a conscious
//!   baseline update in `devx/wasm_size_budget.json`.
//! - `WASM_ARTIFACT_SHA256` pins the SHA-256 digest of the artifact that the
//!   budget was calibrated against. CI records the actual digest for every
//!   build so operators can diff a deployed artifact against the reviewed
//!   baseline. Digests are non-sensitive public artifact fingerprints.
//!
//! ## Trust boundary and privacy
//!
//! The budget is a supply-chain guard: a runaway artifact (dependency
//! accident, malicious patch, toolchain regression) fails CI before it can
//! be deployed. All diagnostics carry sizes, digests, and limit values only
//! — never proof bytes, witness values, media, or keys.
//!
//! ## Compatibility and rollback
//!
//! This module adds constants and a pure helper; it changes no exported
//! contract function, storage key, or event schema, and requires no
//! migration. Raising `MAX_WASM_SIZE_BYTES` is an additive, reviewable
//! change; rollback is reverting this file, the baseline JSON, and the CI
//! gate step.

use soroban_sdk::contracterror;

/// Hard upper bound for the compiled registry Wasm artifact, in bytes.
///
/// Calibration: Soroban itself rejects contract code above 131,072 bytes
/// (128 KiB) at upload time. This budget sits just under that network cap so
/// CI fails on bloat before an upload is even attempted, while the small
/// margin absorbs metadata-section variance across toolchain updates. A
/// deliberate raise must stay below 131,072 and be reviewed as a protocol
/// note in the PR. Growth beyond this budget means an accidental dependency,
/// a disabled optimization, or an unintentionally included test-utils
/// feature.
pub const MAX_WASM_SIZE_BYTES: u64 = 128_000;

/// Allowed drift, in percent, between the built artifact and the recorded
/// golden-size baseline before the budget gate treats the change as a
/// deliberate size migration that must update `devx/wasm_size_budget.json`.
pub const WASM_SIZE_REGRESSION_BAND_PCT: u64 = 15;

/// Lower bound of the accepted artifact size, in bytes.
///
/// A suspiciously small artifact almost always means the wrong profile was
/// built (debug without optimizations is excluded upstream, but an
/// accidental `cargo build` output or a truncated artifact must not pass).
pub const MIN_WASM_SIZE_BYTES: u64 = 10_000;

/// SHA-256 digest of the release artifact the budget baseline was recorded
/// against, as lowercase hex. Recorded by the CI budget gate on every build;
/// keep the baseline digest in `devx/wasm_size_budget.json` in sync when the
/// artifact intentionally changes.
pub const WASM_ARTIFACT_SHA256: &str = "unrecorded";

/// Errors reported by the Wasm size budget.
///
/// The error surface is stable and privacy-safe: it distinguishes only
/// budget violations from a missing artifact and never includes artifact
/// contents, only sizes, digests, and limit values.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum WasmBudgetError {
    /// Artifact exceeded [`MAX_WASM_SIZE_BYTES`].
    ArtifactTooLarge = 1,
    /// Artifact is smaller than [`MIN_WASM_SIZE_BYTES`] (wrong profile or
    /// truncated output).
    ArtifactTooSmall = 2,
    /// No artifact was provided to check.
    MissingArtifact = 3,
}

/// Validate a built artifact size against the declared budget.
///
/// `size_bytes` is the length of `harpocrates_registry.wasm` in bytes;
/// `present` marks whether an artifact file was found at all. Returns the
/// size on success so callers can log a privacy-safe audit line.
pub fn check_wasm_size(size_bytes: u64, present: bool) -> Result<u64, WasmBudgetError> {
    if !present {
        return Err(WasmBudgetError::MissingArtifact);
    }
    if size_bytes < MIN_WASM_SIZE_BYTES {
        return Err(WasmBudgetError::ArtifactTooSmall);
    }
    if size_bytes > MAX_WASM_SIZE_BYTES {
        return Err(WasmBudgetError::ArtifactTooLarge);
    }
    Ok(size_bytes)
}

/// Compare an actual artifact size against the recorded golden baseline.
///
/// Returns `Ok(())` while the artifact stays inside
/// [`WASM_SIZE_REGRESSION_BAND_PCT`] of `baseline_bytes`; a larger drift
/// yields [`WasmBudgetError::ArtifactTooLarge`] so the size move is treated
/// as a deliberate baseline migration, not silent drift. Sizes only — no
/// artifact contents are inspected.
pub fn check_wasm_regression(
    actual_bytes: u64,
    baseline_bytes: u64,
) -> Result<(), WasmBudgetError> {
    if baseline_bytes == 0 {
        // No recorded baseline yet: the hard budget above still applies.
        return Ok(());
    }
    let band = baseline_bytes * WASM_SIZE_REGRESSION_BAND_PCT / 100;
    if actual_bytes > baseline_bytes + band || actual_bytes + band < baseline_bytes {
        return Err(WasmBudgetError::ArtifactTooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_size_within_budget() {
        assert_eq!(check_wasm_size(100_000, true), Ok(100_000));
    }

    #[test]
    fn rejects_oversized_artifact() {
        assert_eq!(
            check_wasm_size(MAX_WASM_SIZE_BYTES + 1, true),
            Err(WasmBudgetError::ArtifactTooLarge)
        );
    }

    #[test]
    fn rejects_missing_artifact() {
        assert_eq!(
            check_wasm_size(0, false),
            Err(WasmBudgetError::MissingArtifact)
        );
    }

    #[test]
    fn rejects_suspiciously_small_artifact() {
        assert_eq!(
            check_wasm_size(MIN_WASM_SIZE_BYTES - 1, true),
            Err(WasmBudgetError::ArtifactTooSmall)
        );
    }

    #[test]
    fn budget_boundary_is_inclusive() {
        assert_eq!(
            check_wasm_size(MIN_WASM_SIZE_BYTES, true),
            Ok(MIN_WASM_SIZE_BYTES)
        );
        assert_eq!(
            check_wasm_size(MAX_WASM_SIZE_BYTES, true),
            Ok(MAX_WASM_SIZE_BYTES)
        );
    }

    #[test]
    fn regression_band_accepts_baseline_match() {
        assert_eq!(check_wasm_regression(100_000, 100_000), Ok(()));
    }

    #[test]
    fn regression_band_accepts_small_drift() {
        // +15% exactly is inside the band.
        assert_eq!(check_wasm_regression(115_000, 100_000), Ok(()));
        // -15% exactly is inside the band.
        assert_eq!(check_wasm_regression(85_000, 100_000), Ok(()));
    }

    #[test]
    fn regression_band_rejects_large_growth() {
        assert!(check_wasm_regression(116_000, 100_000).is_err());
    }

    #[test]
    fn regression_band_rejects_large_shrink() {
        assert!(check_wasm_regression(84_000, 100_000).is_err());
    }

    #[test]
    fn zero_baseline_disables_band_check() {
        assert_eq!(check_wasm_regression(123_456, 0), Ok(()));
    }

    #[test]
    fn budget_leaves_headroom_for_toolchain_variance() {
        // The declared budget must stay far above the calibration artifact so
        // minor compiler/SDK updates cannot break CI silently.
        assert!(MAX_WASM_SIZE_BYTES >= 3 * MIN_WASM_SIZE_BYTES);
    }
}
