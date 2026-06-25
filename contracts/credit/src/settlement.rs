// SPDX-License-Identifier: MIT

//! Default-liquidation settlement module.
//!
//! # What
//!
//! Extracted from [`crate::lifecycle`] to keep that module focused on
//! state-machine transitions. This module owns:
//!
//! - [`liquidation_settlement_key`] — persistent-storage key factory for the
//!   `(borrower, settlement_id)` replay-protection marker.
//! - [`validate_oracle_price`] — oracle circuit-breaker validation helper
//!   called by the public entrypoint in [`crate::lib`] before the accounting
//!   write occurs.
//! - [`settle_default_liquidation`] — accounting half of the cross-contract
//!   handoff with the auction contract; replay-protected, requires the credit
//!   line to be `Defaulted`, and auto-closes it when `utilized_amount` reaches
//!   zero.
//!
//! # Why (settlement replay safety)
//!
//! The `(borrower, settlement_id)` marker is the credit-side half of a
//! two-sided replay barrier. The auction contract enforces the same property
//! on `auction_id` via `AuctionKey::LiquidationSettled(auction_id)`. Together
//! they ensure a defaulted line cannot be settled twice by the same admin
//! transaction, by a stale `settlement_id` re-run, or by the auction contract
//! returning a duplicate value. The cross-contract return is additionally
//! asserted equal to the admin-supplied `recovered_amount` in
//! [`crate::lib::Credit::settle_default_liquidation`]; mismatch reverts
//! `InvalidAmount = 5`.
//!
//! # Storage layout
//!
//! - **Settlement markers** — Persistent storage, keyed by
//!   `(Symbol("liq_seen"), borrower, settlement_id)`. Presence means the
//!   settlement has already been applied. Replay reverts with
//!   `ContractError::AlreadyInitialized = 14`.
//!
//! # Oracle circuit-breaker
//!
//! When [`crate::storage::get_oracle_config`] returns `Some(cfg)`, the
//! entrypoint in `lib.rs` calls [`validate_oracle_price`] before the
//! accounting write. The helper checks:
//!
//! 1. `oracle_price` is present and positive.
//! 2. The stored last-price timestamp is no older than `cfg.max_age_seconds`.
//! 3. The deviation from the last accepted price is ≤ `cfg.max_deviation_bps`.
//!
//! On success it persists the new price and timestamp via
//! [`crate::storage::set_oracle_last_price`].

use crate::auth::require_admin_auth;
use crate::events::{
    publish_credit_line_event, publish_default_liquidation_settled_event, CreditLineEvent,
    DefaultLiquidationSettledEvent,
};
use crate::math_utils::compute_deviation_bps;
use crate::storage::{
    assert_not_paused, clear_repayment_schedule, persist_credit_line,
};
use crate::types::{ContractError, CreditLineData, CreditStatus, OracleConfig};
use soroban_sdk::{symbol_short, Address, Env, Symbol};

// ── Replay-protection key ─────────────────────────────────────────────────────

/// Build the persistent-storage key used to record that a particular
/// `(borrower, settlement_id)` pair has been settled.
///
/// # Key layout
/// ```text
/// (Symbol("liq_seen"), borrower: Address, settlement_id: Symbol)
/// ```
///
/// # Storage
/// - **Type**: Persistent storage (independent TTL per settlement marker)
/// - **Presence**: Indicates the settlement has already been applied.
///   Replay attempts revert with `ContractError::AlreadyInitialized = 14`.
///
/// This function is `pub(crate)` so that `lifecycle.rs` can delegate to it
/// without re-exporting the raw tuple type across module boundaries.
pub(crate) fn liquidation_settlement_key(
    borrower: &Address,
    settlement_id: &Symbol,
) -> (Symbol, Address, Symbol) {
    (
        symbol_short!("liq_seen"),
        borrower.clone(),
        settlement_id.clone(),
    )
}

// ── Oracle circuit-breaker validation ────────────────────────────────────────

/// Validate the oracle price supplied to `settle_default_liquidation`.
///
/// Called by the public entrypoint in [`crate::lib`] **before** the
/// accounting write, so a stale or deviated price aborts the entire
/// settlement atomically.
///
/// # Behaviour
///
/// 1. Requires `oracle_price` to be present (`Some`) and positive.
/// 2. If a previous accepted price exists, checks that the ledger age since
///    that price's timestamp does not exceed `cfg.max_age_seconds`.
/// 3. If a previous accepted price value exists, checks that the absolute
///    deviation in basis points does not exceed `cfg.max_deviation_bps`.
/// 4. On passing all checks, persists `(price, now)` via
///    [`crate::storage::set_oracle_last_price`] and emits
///    `publish_oracle_price_accepted_event`.
///
/// # Parameters
/// - `env`: The Soroban environment.
/// - `cfg`: The oracle circuit-breaker configuration loaded by the caller.
/// - `oracle_price`: The price feed value supplied by the admin.
///
/// # Errors
/// - `ContractError::OraclePriceInvalid` — price is `None` or ≤ 0, or
///   deviation computation overflows.
/// - `ContractError::OraclePriceStale` — last-price timestamp is older than
///   `cfg.max_age_seconds`.
/// - `ContractError::OraclePriceDeviation` — deviation from last accepted
///   price exceeds `cfg.max_deviation_bps`.
pub fn validate_oracle_price(env: &Env, cfg: &OracleConfig, oracle_price: Option<i128>) {
    use crate::events::publish_oracle_price_accepted_event;

    let price = match oracle_price {
        Some(p) => p,
        None => env.panic_with_error(ContractError::OraclePriceInvalid),
    };

    if price <= 0 {
        env.panic_with_error(ContractError::OraclePriceInvalid);
    }

    let now = env.ledger().timestamp();

    // Staleness check — only applies when a previous price timestamp exists.
    if let Some(last_ts) = crate::storage::get_oracle_last_price_ts(env) {
        let age = now.saturating_sub(last_ts);
        if age > cfg.max_age_seconds {
            env.panic_with_error(ContractError::OraclePriceStale);
        }

        // Deviation check — only applies when both a timestamp and a price exist.
        if let Some(last_price) = crate::storage::get_oracle_last_price(env) {
            let deviation = compute_deviation_bps(price, last_price)
                .unwrap_or_else(|| env.panic_with_error(ContractError::OraclePriceInvalid));
            if deviation > cfg.max_deviation_bps {
                env.panic_with_error(ContractError::OraclePriceDeviation);
            }
        }
    }

    // Persist the newly accepted price and timestamp atomically.
    crate::storage::set_oracle_last_price(env, price, now);
    publish_oracle_price_accepted_event(env, price, now);
}

// ── Accounting settlement ─────────────────────────────────────────────────────

/// Apply auction liquidation proceeds to a defaulted credit line (admin only).
///
/// This is the **accounting half** of the cross-contract handoff. No token
/// transfer occurs here. Off-chain orchestration is responsible for ensuring
/// that auction proceeds are in protocol custody before this function is
/// called.
///
/// # Pre-conditions (enforced by caller, [`crate::lib::Credit::settle_default_liquidation`])
///
/// - Reentrancy guard is set before this call and cleared after.
/// - Oracle price has been validated via [`validate_oracle_price`] (when a
///   config is present).
/// - Auction contract hook has been called and its return value asserted equal
///   to `recovered_amount` (when an auction address is configured).
///
/// # State transitions
///
/// | `utilized_amount` after deduction | New `status`        |
/// |----------------------------------|---------------------|
/// | > 0                              | Remains `Defaulted` |
/// | == 0                             | `Closed`            |
///
/// # Replay protection
///
/// Before any mutation the function checks for the presence of
/// `liquidation_settlement_key(borrower, settlement_id)` in persistent
/// storage. If found, it reverts with `ContractError::AlreadyInitialized`.
/// On success it writes `true` to that key.
///
/// # Parameters
/// - `env`: The Soroban environment.
/// - `borrower`: Address whose credit line is being settled.
/// - `recovered_amount`: Proceeds recovered from the auction. Must be > 0
///   and ≤ `credit_line.utilized_amount`.
/// - `settlement_id`: Unique auction identifier; combined with `borrower`
///   to form the replay-protection key.
///
/// # Errors
/// - `ContractError::InvalidAmount` — `recovered_amount` ≤ 0.
/// - `ContractError::AlreadyInitialized` — settlement already applied.
/// - `ContractError::CreditLineNotFound` — no credit line for `borrower`.
/// - `ContractError::CreditLineDefaulted` — credit line is not `Defaulted`.
/// - `ContractError::OverLimit` — `recovered_amount` > `utilized_amount`.
/// - `ContractError::Overflow` — subtraction underflow (should be
///   unreachable after the `OverLimit` guard).
///
/// # Events
/// - `("credit", "settled")` [`DefaultLiquidationSettledEvent`] — always.
/// - `("credit", "closed")` [`CreditLineEvent`] — only when the line is
///   fully repaid and transitions to `Closed`.
pub fn settle_default_liquidation(
    env: Env,
    borrower: Address,
    recovered_amount: i128,
    settlement_id: Symbol,
) {
    assert_not_paused(&env);
    require_admin_auth(&env);

    if recovered_amount <= 0 {
        env.panic_with_error(ContractError::InvalidAmount);
    }

    // Replay-protection: revert if this (borrower, settlement_id) has been seen.
    let settlement_key = liquidation_settlement_key(&borrower, &settlement_id);
    if env.storage().persistent().has(&settlement_key) {
        // AlreadyInitialized (discriminant 14) is the canonical replay-barrier error.
        env.panic_with_error(ContractError::AlreadyInitialized);
    }

    let stored_line: CreditLineData = env
        .storage()
        .persistent()
        .get(&borrower)
        .unwrap_or_else(|| env.panic_with_error(ContractError::CreditLineNotFound));
    let previous_utilized = stored_line.utilized_amount;

    // Capitalize any pending interest before the accounting write.
    let mut credit_line = crate::accrual::apply_accrual(&env, stored_line);

    if credit_line.status != CreditStatus::Defaulted {
        env.panic_with_error(ContractError::CreditLineDefaulted);
    }

    if recovered_amount > credit_line.utilized_amount {
        env.panic_with_error(ContractError::OverLimit);
    }

    credit_line.utilized_amount = credit_line
        .utilized_amount
        .checked_sub(recovered_amount)
        .unwrap_or_else(|| env.panic_with_error(ContractError::Overflow));

    // Auto-close the line when fully repaid.
    if credit_line.utilized_amount == 0 {
        credit_line.status = CreditStatus::Closed;
    }

    persist_credit_line(&env, &borrower, &credit_line, previous_utilized);

    if credit_line.status == CreditStatus::Closed {
        clear_repayment_schedule(&env, &borrower);
    }

    // Record the settlement marker to prevent replay.
    env.storage().persistent().set(&settlement_key, &true);

    // Emit closed event when the line was fully settled.
    if credit_line.status == CreditStatus::Closed {
        publish_credit_line_event(
            &env,
            (symbol_short!("credit"), symbol_short!("closed")),
            CreditLineEvent {
                borrower: borrower.clone(),
                status: CreditStatus::Closed,
                credit_limit: credit_line.credit_limit,
                interest_rate_bps: credit_line.interest_rate_bps,
                risk_score: credit_line.risk_score,
            },
        );
    }

    // Always emit the settlement event.
    publish_default_liquidation_settled_event(
        &env,
        DefaultLiquidationSettledEvent {
            borrower,
            settlement_id,
            recovered_amount,
            remaining_utilized_amount: credit_line.utilized_amount,
            status: credit_line.status,
        },
    );
}
