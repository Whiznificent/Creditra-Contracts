// SPDX-License-Identifier: MIT

//! Interest accrual logic for credit lines.
//!
//! This module computes and applies pro-rated interest to a [`CreditLineData`]
//! record. Interest is calculated using a 365-day year and capitalised into
//! `accrued_interest`; it does **not** automatically increase `utilized_amount`
//! — the caller decides when to capitalise.

#![warn(missing_docs)]

use crate::math_utils::prorate_interest;
use crate::types::CreditLineData;
use soroban_sdk::Env;

/// Compute and apply accrued interest to a credit line for the elapsed period.
///
/// Calculates the interest owed since `credit_line.last_accrual_ts` using
/// [`prorate_interest`], adds it to `credit_line.accrued_interest`, and
/// updates `credit_line.last_accrual_ts` to `now`.
///
/// # How interest is computed
/// ```text
/// elapsed  = now - last_accrual_ts          (seconds)
/// interest = principal * rate_bps * elapsed
///            ────────────────────────────────
///                  10_000 * 31_536_000
/// ```
/// where `principal` is `credit_line.utilized_amount` and `rate_bps` is
/// `credit_line.interest_rate_bps`.
///
/// # Rounding
/// Truncates toward zero via [`prorate_interest`]. Sub-unit interest amounts
/// accrue as `0` for that period and are not carried forward.
///
/// # Parameters
/// - `env`:         The Soroban environment; used to read the current ledger
///                  timestamp via `env.ledger().timestamp()`.
/// - `credit_line`: Mutable reference to the credit line to update. Both
///                  `accrued_interest` and `last_accrual_ts` are modified
///                  in-place. The caller is responsible for persisting the
///                  updated record to storage.
///
/// # Returns
/// The amount of interest accrued in this call (may be `0` if `elapsed == 0`,
/// `utilized_amount == 0`, or the computed amount truncates to zero).
///
/// # Panics
/// - If `principal * rate_bps * elapsed` overflows `i128`.
/// - If adding interest to `credit_line.accrued_interest` overflows `i128`.
///
/// # Example
/// ```text
/// // Credit line: 1_000_000 utilized at 500 bps (5% p.a.)
/// // last_accrual_ts = 0, now = 86_400 (1 day later)
/// // interest = 1_000_000 * 500 * 86_400 / 315_360_000_000 = 137
/// // After call: accrued_interest += 137, last_accrual_ts = 86_400
/// ```
pub fn apply_accrued_interest(env: &Env, credit_line: &mut CreditLineData) -> i128 {
    let now = env.ledger().timestamp();
    let last = credit_line.last_accrual_ts;
    let elapsed = now.saturating_sub(last);
    let interest = prorate_interest(
        credit_line.utilized_amount,
        credit_line.interest_rate_bps,
        elapsed,
    );
    credit_line.accrued_interest = credit_line
        .accrued_interest
        .checked_add(interest)
        .expect("apply_accrual: accrued_interest overflowed i128");
    credit_line.last_accrual_ts = now;
    interest
}

use crate::events::{publish_interest_accrued_event, InterestAccruedEvent};
use crate::types::{ContractError, CreditStatus, GracePeriodConfig, GraceWaiverMode};

pub(crate) const SECONDS_PER_YEAR: u64 = 31_536_000;

/// Compute simple interest: `utilized * rate_bps * seconds / (10_000 * SECONDS_PER_YEAR)`.
///
/// # Overflow behavior — **revert with `ContractError::Overflow`**
/// All intermediate multiplications use `checked_mul`. If any step would exceed
/// `i128::MAX` the function returns `Err(ContractError::Overflow)` so the caller
/// can propagate it via `env.panic_with_error`. No silent wrapping or saturation
/// occurs; the contract reverts deterministically.
fn compute_interest(
    utilized: i128,
    rate_bps: i128,
    seconds: i128,
) -> Result<i128, ContractError> {
    let denominator: i128 = 10_000 * (SECONDS_PER_YEAR as i128);
    let intermediate = utilized
        .checked_mul(rate_bps)
        .and_then(|v| v.checked_mul(seconds));
    match intermediate {
        Some(val) => Ok(val / denominator),
        None => Err(ContractError::Overflow),
    }
}

/// Apply interest accrual to a credit line and return the updated line.
///
/// Reads the optional [`GracePeriodConfig`] from instance storage to determine
/// the effective rate for Suspended lines within their grace window.
///
/// # Grace period interaction
/// - If the line is Suspended and a grace period policy is configured, the
///   effective rate is reduced (or zeroed) for the portion of `elapsed` that
///   falls within the grace window.
/// - If the grace window expires mid-period, the elapsed time is split: the
///   in-window portion uses the waiver rate and the post-window portion uses
///   the full rate.
/// - If no policy is configured, or the line is not Suspended, normal accrual
///   applies unchanged.
///
/// # Overflow behavior — **revert with `ContractError::Overflow`**
/// Every arithmetic step that could overflow uses checked arithmetic. If any
/// intermediate multiplication in `compute_interest` overflows `i128`, or if
/// adding the newly accrued amount to `utilized_amount` / `accrued_interest`
/// would overflow, the function reverts deterministically via
/// `env.panic_with_error(ContractError::Overflow)`. No silent wrapping or
/// saturation occurs anywhere in this function.
pub fn apply_accrual(env: &Env, mut line: CreditLineData) -> CreditLineData {
    let now = env.ledger().timestamp();

    if now <= line.last_accrual_ts {
        return line;
    }

    if line.utilized_amount == 0 {
        line.last_accrual_ts = now;
        return line;
    }

    let utilized = line.utilized_amount;
    let full_rate = line.interest_rate_bps as i128;
    let accrual_start = line.last_accrual_ts;

    let accrued = if line.status == CreditStatus::Suspended {
        let grace_cfg: Option<GracePeriodConfig> = env
            .storage()
            .instance()
            .get(&crate::storage::grace_period_key(env));

        match grace_cfg {
            Some(cfg) if cfg.grace_period_seconds > 0 => {
                let grace_end = line.suspension_ts.saturating_add(cfg.grace_period_seconds);

                if now <= grace_end {
                    // Entire period is within the grace window
                    let seconds = (now - accrual_start) as i128;
                    match cfg.waiver_mode {
                        GraceWaiverMode::FullWaiver => 0,
                        GraceWaiverMode::ReducedRate => {
                            compute_interest(utilized, cfg.reduced_rate_bps as i128, seconds)
                                .unwrap_or_else(|e| env.panic_with_error(e))
                        }
                    }
                } else if accrual_start >= grace_end {
                    // Entire period is after grace window
                    let seconds = (now - accrual_start) as i128;
                    compute_interest(utilized, full_rate, seconds)
                        .unwrap_or_else(|e| env.panic_with_error(e))
                } else {
                    // Period straddles the grace boundary
                    let in_window_secs = (grace_end - accrual_start) as i128;
                    let post_window_secs = (now - grace_end) as i128;

                    let in_window_interest = match cfg.waiver_mode {
                        GraceWaiverMode::FullWaiver => 0,
                        GraceWaiverMode::ReducedRate => {
                            compute_interest(utilized, cfg.reduced_rate_bps as i128, in_window_secs)
                                .unwrap_or_else(|e| env.panic_with_error(e))
                        }
                    };
                    let post_window_interest =
                        compute_interest(utilized, full_rate, post_window_secs)
                            .unwrap_or_else(|e| env.panic_with_error(e));
                    // Checked addition of the two sub-period interests — revert on overflow.
                    in_window_interest
                        .checked_add(post_window_interest)
                        .unwrap_or_else(|| env.panic_with_error(ContractError::Overflow))
                }
            }
            _ => {
                let seconds = (now - accrual_start) as i128;
                compute_interest(utilized, full_rate, seconds)
                    .unwrap_or_else(|e| env.panic_with_error(e))
            }
        }
    } else {
        let seconds = (now - accrual_start) as i128;
        compute_interest(utilized, full_rate, seconds)
            .unwrap_or_else(|e| env.panic_with_error(e))
    };

    if accrued > 0 {
        // Accumulate accrued interest into utilized_amount — revert on overflow.
        line.utilized_amount = line
            .utilized_amount
            .checked_add(accrued)
            .unwrap_or_else(|| env.panic_with_error(ContractError::Overflow));
        // Accumulate running accrued_interest total — revert on overflow.
        line.accrued_interest = line
            .accrued_interest
            .checked_add(accrued)
            .unwrap_or_else(|| env.panic_with_error(ContractError::Overflow));

        publish_interest_accrued_event(
            env,
            InterestAccruedEvent {
                borrower: line.borrower.clone(),
                accrued_amount: accrued,
                new_utilized_amount: line.utilized_amount,
            },
        );
    }

    line.last_accrual_ts = now;
    line
}
