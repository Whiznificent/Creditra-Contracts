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
pub fn apply_accrual(env: &Env, credit_line: &mut CreditLineData) -> i128 {
    let now = env.ledger().timestamp();
    let last = credit_line.last_accrual_ts;
    let elapsed = now.saturating_sub(last);
    let interest = prorate_interest(
        credit_line.utilized_amount,
        credit_line.interest_rate_bps,
        elapsed,
