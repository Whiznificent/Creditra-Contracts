use crate::events::{publish_drawn_event, publish_repayment_event, DrawnEvent, RepaymentEvent};
use crate::storage::{
    clear_reentrancy_guard, set_reentrancy_guard, DataKey, CREDIT_LINE_TTL_EXTEND_TO,
    CREDIT_LINE_TTL_THRESHOLD,
};
use crate::types::{ContractError, CreditLineData, CreditStatus};
use soroban_sdk::{token, Address, Env};

pub fn draw_credit(env: Env, borrower: Address, amount: i128) {
    set_reentrancy_guard(&env);
    borrower.require_auth();

    if amount <= 0 {
        clear_reentrancy_guard(&env);
        panic!("amount must be positive");
    }

    let token_address: Option<Address> = env.storage().instance().get(&DataKey::LiquidityToken);
    let reserve_address: Address = env
        .storage()
        .instance()
        .get(&DataKey::LiquiditySource)
        .unwrap_or_else(|| env.current_contract_address());

    let mut credit_line: CreditLineData = env
        .storage()
        .persistent()
        .get(&borrower)
        .unwrap_or_else(|| {
            clear_reentrancy_guard(&env);
            env.panic_with_error(ContractError::CreditLineNotFound)
        });

    if credit_line.borrower != borrower {
        clear_reentrancy_guard(&env);
        panic!("Borrower mismatch for credit line");
    }

    if credit_line.status == CreditStatus::Closed {
        clear_reentrancy_guard(&env);
        env.panic_with_error(ContractError::CreditLineClosed);
    }

    if credit_line.status == CreditStatus::Suspended {
        clear_reentrancy_guard(&env);
        panic!("credit line is suspended");
    }

    if credit_line.status == CreditStatus::Defaulted {
        clear_reentrancy_guard(&env);
        panic!("credit line is defaulted");
    }

    if credit_line.status != CreditStatus::Active {
        clear_reentrancy_guard(&env);
        env.panic_with_error(ContractError::InvalidAmount);
    }

    let updated_utilized = credit_line
        .utilized_amount
        .checked_add(amount)
        .unwrap_or_else(|| {
            clear_reentrancy_guard(&env);
            panic!("overflow");
        });

    if updated_utilized > credit_line.credit_limit {
        clear_reentrancy_guard(&env);
        panic!("exceeds credit limit");
    }

    if let Some(token_address) = token_address {
        let token_client = token::Client::new(&env, &token_address);
        let reserve_balance = token_client.balance(&reserve_address);
        if reserve_balance < amount {
            clear_reentrancy_guard(&env);
            panic!("Insufficient liquidity reserve for requested draw amount");
        }

        token_client.transfer(&reserve_address, &borrower, &amount);
    }

    credit_line.utilized_amount = updated_utilized;
    env.storage().persistent().set(&borrower, &credit_line);
    // Bump TTL: every draw is an interaction that resets the expiry window.
    env.storage()
        .persistent()
        .extend_ttl(&borrower, CREDIT_LINE_TTL_THRESHOLD, CREDIT_LINE_TTL_EXTEND_TO);
    let timestamp = env.ledger().timestamp();
    publish_drawn_event(
        &env,
        DrawnEvent {
            borrower,
            amount,
            new_utilized_amount: updated_utilized,
            timestamp,
        },
    );
    clear_reentrancy_guard(&env);
}

pub fn repay_credit(env: Env, borrower: Address, amount: i128) {
    // --- Reentrancy guard (defense-in-depth) ---
    set_reentrancy_guard(&env);

    // --- Auth: only the borrower may repay their own line ---
    borrower.require_auth();

    // --- Input validation ---
    if amount <= 0 {
        clear_reentrancy_guard(&env);
        env.panic_with_error(ContractError::InvalidAmount);
    }

    // --- Load credit line ---
    let mut credit_line: CreditLineData = env
        .storage()
        .persistent()
        .get(&borrower)
        .unwrap_or_else(|| {
            clear_reentrancy_guard(&env);
            env.panic_with_error(ContractError::CreditLineNotFound)
        });

    // --- Status check: only Closed is disallowed ---
    if credit_line.status == CreditStatus::Closed {
        clear_reentrancy_guard(&env);
        env.panic_with_error(ContractError::CreditLineClosed);
    }

    // --- Compute effective repayment (cap at outstanding utilization) ---
    // This prevents over-pulling tokens and keeps accounting correct.
    let effective_repay = if amount > credit_line.utilized_amount {
        credit_line.utilized_amount
    } else {
        amount
    };

    // --- Token transfer (when liquidity token is configured) ---
    // We check allowance and balance *before* mutating state so that a
    // failed transfer reverts cleanly without partial state changes.
    if effective_repay > 0 {
        let token_address: Option<Address> =
            env.storage().instance().get(&DataKey::LiquidityToken);

        if let Some(token_address) = token_address {
            let reserve_address: Address = env
                .storage()
                .instance()
                .get(&DataKey::LiquiditySource)
                .unwrap_or_else(|| env.current_contract_address());

            let token_client = token::Client::new(&env, &token_address);
            let contract_address = env.current_contract_address();

            // Guard: allowance must cover the effective repayment.
            let allowance = token_client.allowance(&borrower, &contract_address);
            if allowance < effective_repay {
                clear_reentrancy_guard(&env);
                panic!("Insufficient allowance");
            }

            // Guard: borrower must actually hold the tokens.
            let balance = token_client.balance(&borrower);
            if balance < effective_repay {
                clear_reentrancy_guard(&env);
                panic!("Insufficient balance");
            }

            // Pull tokens from borrower → liquidity source via transfer_from.
            token_client.transfer_from(
                &contract_address,
                &borrower,
                &reserve_address,
                &effective_repay,
            );
        }
    }

    // --- Update state ---
    let new_utilized = credit_line
        .utilized_amount
        .saturating_sub(effective_repay)
        .max(0);
    credit_line.utilized_amount = new_utilized;
    env.storage().persistent().set(&borrower, &credit_line);
    // Bump TTL: every repayment is an interaction that resets the expiry window.
    env.storage()
        .persistent()
        .extend_ttl(&borrower, CREDIT_LINE_TTL_THRESHOLD, CREDIT_LINE_TTL_EXTEND_TO);

    // --- Emit event ---
    let timestamp = env.ledger().timestamp();
    publish_repayment_event(
        &env,
        RepaymentEvent {
            borrower,
            amount: effective_repay,
            new_utilized_amount: new_utilized,
            timestamp,
        },
    );

    // --- Release reentrancy guard ---
    clear_reentrancy_guard(&env);
}
