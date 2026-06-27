// SPDX-License-Identifier: MIT

//! Credit-line lifecycle operations: open, suspend, close, default, reinstate.
//!
//! # TTL bumping
//! Every function that writes a credit-line entry to persistent storage also
//! calls [`extend_ttl`](soroban_sdk::storage::Persistent::extend_ttl) to keep
//! the entry live for [`CREDIT_LINE_TTL_EXTEND_TO`] ledgers.  The threshold
//! [`CREDIT_LINE_TTL_THRESHOLD`] ensures we only pay for the extension when
//! there is a real risk of expiry.

use crate::auth::{require_admin, require_admin_auth};
use crate::events::{publish_credit_line_event, CreditLineEvent};
use crate::storage::{CREDIT_LINE_TTL_EXTEND_TO, CREDIT_LINE_TTL_THRESHOLD};
use crate::types::{CreditLineData, CreditStatus};
use soroban_sdk::{symbol_short, Address, Env};

/// Helper: bump the TTL of a borrower's persistent credit-line entry.
///
/// Should be called after every read **or** write that constitutes an
/// "interaction" with the credit line so the ledger entry never silently
/// expires while the line is still in use.
fn bump_credit_line_ttl(env: &Env, borrower: &Address) {
    env.storage()
        .persistent()
        .extend_ttl(borrower, CREDIT_LINE_TTL_THRESHOLD, CREDIT_LINE_TTL_EXTEND_TO);
}

/// Open a new credit line for a borrower (admin only).
///
/// # Parameters
/// - `borrower`: Address of the borrower.
/// - `credit_limit`: Maximum drawable amount (must be > 0).
/// - `interest_rate_bps`: Annual interest rate in basis points (0–10 000).
/// - `risk_score`: Borrower risk score (0–100).
///
/// # Panics
/// - If `credit_limit` ≤ 0, `interest_rate_bps` > 10 000, or `risk_score` > 100.
/// - If the borrower already has an Active credit line.
///
/// # Events
/// Emits a `("credit", "opened")` [`CreditLineEvent`].
pub fn open_credit_line(
    env: Env,
    borrower: Address,
    credit_limit: i128,
    interest_rate_bps: u32,
    risk_score: u32,
) {
    assert!(credit_limit > 0, "credit_limit must be greater than zero");
    assert!(
        interest_rate_bps <= 10_000,
        "interest_rate_bps cannot exceed 10000 (100%)"
    );
    assert!(risk_score <= 100, "risk_score must be between 0 and 100");

    // Prevent overwriting an existing Active credit line.
    if let Some(existing) = env
        .storage()
        .persistent()
        .get::<Address, CreditLineData>(&borrower)
    {
        assert!(
            existing.status != CreditStatus::Active,
            "borrower already has an active credit line"
        );
    }

    let credit_line = CreditLineData {
        borrower: borrower.clone(),
        credit_limit,
        utilized_amount: 0,
        interest_rate_bps,
        risk_score,
        status: CreditStatus::Active,
        last_rate_update_ts: 0,
        accrued_interest: 0,
        last_accrual_ts: 0,
    };

    env.storage().persistent().set(&borrower, &credit_line);
    // Bump TTL: newly opened lines start with a full TTL window.
    bump_credit_line_ttl(&env, &borrower);

    publish_credit_line_event(
        &env,
        (symbol_short!("credit"), symbol_short!("opened")),
        CreditLineEvent {
            event_type: symbol_short!("opened"),
            borrower: borrower.clone(),
            status: CreditStatus::Active,
            credit_limit,
            interest_rate_bps,
            risk_score,
        },
    );
}

/// Suspend a credit line temporarily (admin only).
///
/// Only lines in [`CreditStatus::Active`] status may be suspended.
///
/// # Parameters
/// - `borrower`: The borrower's address.
///
/// # Panics
/// - If no credit line exists for the given borrower.
/// - If the credit line is not currently Active.
///
/// # Events
/// Emits a `("credit", "suspend")` [`CreditLineEvent`].
pub fn suspend_credit_line(env: Env, borrower: Address) {
    require_admin_auth(&env);
    let mut credit_line: CreditLineData = env
        .storage()
        .persistent()
        .get(&borrower)
        .expect("Credit line not found");

    if credit_line.status != CreditStatus::Active {
        panic!("Only active credit lines can be suspended");
    }

    credit_line.status = CreditStatus::Suspended;
    env.storage().persistent().set(&borrower, &credit_line);
    // Bump TTL: interacting with a suspended line keeps it live.
    bump_credit_line_ttl(&env, &borrower);

    publish_credit_line_event(
        &env,
        (symbol_short!("credit"), symbol_short!("suspend")),
        CreditLineEvent {
            event_type: symbol_short!("suspend"),
            borrower: borrower.clone(),
            status: CreditStatus::Suspended,
            credit_limit: credit_line.credit_limit,
            interest_rate_bps: credit_line.interest_rate_bps,
            risk_score: credit_line.risk_score,
        },
    );
}

/// Close a credit line. Callable by admin (force-close) or by borrower
/// when utilization is zero. Idempotent if already Closed.
///
/// # Arguments
/// * `closer` - Must be either the contract admin (can close regardless of
///   utilization) or the borrower (can close only when `utilized_amount` is zero).
///
/// # Panics
/// - If the credit line does not exist.
/// - If `closer` is not the admin or borrower.
/// - If the borrower attempts to close while `utilized_amount != 0`.
///
/// # Events
/// Emits a `("credit", "closed")` [`CreditLineEvent`].
pub fn close_credit_line(env: Env, borrower: Address, closer: Address) {
    closer.require_auth();

    let admin: Address = require_admin(&env);

    let mut credit_line: CreditLineData = env
        .storage()
        .persistent()
        .get(&borrower)
        .expect("Credit line not found");

    if credit_line.status == CreditStatus::Closed {
        return;
    }

    let allowed = closer == admin || (closer == borrower && credit_line.utilized_amount == 0);

    if !allowed {
        if closer == borrower {
            panic!("cannot close: utilized amount not zero");
        }
        panic!("unauthorized");
    }

    credit_line.status = CreditStatus::Closed;
    env.storage().persistent().set(&borrower, &credit_line);
    // Bump TTL: keep the closed record live so history is queryable.
    bump_credit_line_ttl(&env, &borrower);

    publish_credit_line_event(
        &env,
        (symbol_short!("credit"), symbol_short!("closed")),
        CreditLineEvent {
            event_type: symbol_short!("closed"),
            borrower: borrower.clone(),
            status: CreditStatus::Closed,
            credit_limit: credit_line.credit_limit,
            interest_rate_bps: credit_line.interest_rate_bps,
            risk_score: credit_line.risk_score,
        },
    );
}

/// Mark a credit line as defaulted (admin only).
///
/// Transition: Active or Suspended → Defaulted.
/// After this, `draw_credit` is disabled and `repay_credit` remains allowed.
///
/// # Panics
/// - If no credit line exists for the given borrower.
///
/// # Events
/// Emits a `("credit", "default")` [`CreditLineEvent`].
pub fn default_credit_line(env: Env, borrower: Address) {
    require_admin_auth(&env);
    let mut credit_line: CreditLineData = env
        .storage()
        .persistent()
        .get(&borrower)
        .expect("Credit line not found");

    credit_line.status = CreditStatus::Defaulted;
    env.storage().persistent().set(&borrower, &credit_line);
    // Bump TTL: defaulted lines must remain queryable during workout period.
    bump_credit_line_ttl(&env, &borrower);

    publish_credit_line_event(
        &env,
        (symbol_short!("credit"), symbol_short!("default")),
        CreditLineEvent {
            event_type: symbol_short!("default"),
            borrower: borrower.clone(),
            status: CreditStatus::Defaulted,
            credit_limit: credit_line.credit_limit,
            interest_rate_bps: credit_line.interest_rate_bps,
            risk_score: credit_line.risk_score,
        },
    );
}

/// Reinstate a defaulted credit line to Active (admin only).
///
/// Allowed only when status is Defaulted. Transition: Defaulted → Active.
///
/// # Panics
/// - If no credit line exists for the given borrower.
/// - If the credit line is not currently Defaulted.
///
/// # Events
/// Emits a `("credit", "reinstate")` [`CreditLineEvent`].
pub fn reinstate_credit_line(env: Env, borrower: Address) {
    require_admin_auth(&env);

    let mut credit_line: CreditLineData = env
        .storage()
        .persistent()
        .get(&borrower)
        .expect("Credit line not found");

    if credit_line.status != CreditStatus::Defaulted {
        panic!("credit line is not defaulted");
    }

    credit_line.status = CreditStatus::Active;
    env.storage().persistent().set(&borrower, &credit_line);
    // Bump TTL: reinstated lines restart their active lifecycle.
    bump_credit_line_ttl(&env, &borrower);

    publish_credit_line_event(
        &env,
        (symbol_short!("credit"), symbol_short!("reinstate")),
        CreditLineEvent {
            event_type: symbol_short!("reinstate"),
            borrower: borrower.clone(),
            status: CreditStatus::Active,
            credit_limit: credit_line.credit_limit,
            interest_rate_bps: credit_line.interest_rate_bps,
            risk_score: credit_line.risk_score,
        },
    );
}
