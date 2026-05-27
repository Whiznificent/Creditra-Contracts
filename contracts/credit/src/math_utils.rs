// SPDX-License-Identifier: MIT

#![warn(missing_docs)]

// Pure integer arithmetic helpers used across the credit contract.

/// Rounding mode for fixed-point helpers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rounding {
    /// Round down by truncating the remainder.
    Floor,
    /// Round up when the division leaves any remainder.
    Ceil,
}

/// Divide `a * numerator` by `denominator` with explicit rounding.
pub fn mul_div(a: u128, numerator: u128, denominator: u128, rounding: Rounding) -> u128 {
    assert!(denominator != 0, "math_utils: division by zero");
    let product = a.checked_mul(numerator).expect("math_utils: mul overflow");
    let quotient = product / denominator;
    match rounding {
        Rounding::Floor => quotient,
        Rounding::Ceil => {
            if product % denominator != 0 {
                quotient.checked_add(1).expect("math_utils: ceil overflow")
            } else {
                quotient
            }
        }
    }
}

/// Scale an amount up by 10^18.
pub fn scale_up(amount: u128) -> u128 {
    amount
        .checked_mul(1_000_000_000_000_000_000_u128)
        .expect("math_utils: scale_up overflow")
}

/// Scale an amount down by 10^18 with explicit rounding.
pub fn scale_down(amount: u128, rounding: Rounding) -> u128 {
    const SCALE: u128 = 1_000_000_000_000_000_000_u128;
    let quotient = amount / SCALE;
    match rounding {
        Rounding::Floor => quotient,
        Rounding::Ceil => {
            if amount % SCALE != 0 {
                quotient.checked_add(1).expect("math_utils: scale_down ceil overflow")
            } else {
                quotient
            }
        }
    }
}

/// Apply a basis-point rate to an amount.
pub fn apply_bps(amount: u128, rate_bps: u32, rounding: Rounding) -> u128 {
    mul_div(amount, rate_bps as u128, 10_000, rounding)
}

/// Compute pro-rated interest over `elapsed_secs` at `rate_bps`.
pub fn prorate_interest(principal: i128, rate_bps: u32, elapsed_secs: u64) -> i128 {
    const SECONDS_PER_YEAR: i128 = 31_536_000;
    const BPS_DENOMINATOR: i128 = 10_000;

    if elapsed_secs == 0 || principal == 0 {
        return 0;
    }

    let numerator = principal
        .checked_mul(rate_bps as i128)
        .expect("prorate_interest: principal * rate_bps overflowed i128")
        .checked_mul(elapsed_secs as i128)
        .expect("prorate_interest: product with elapsed_secs overflowed i128");

    let denominator = BPS_DENOMINATOR
        .checked_mul(SECONDS_PER_YEAR)
        .expect("prorate_interest: denominator overflowed i128");

    numerator / denominator
}
