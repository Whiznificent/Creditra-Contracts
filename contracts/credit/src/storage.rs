use soroban_sdk::{contracttype, Env, Symbol};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    LiquidityToken,
    LiquiditySource,
}

/// Minimum TTL threshold for credit-line persistent entries.
/// If the remaining TTL falls below this ledger count we extend it.
/// Approximately 1 day at the Stellar Mainnet rate of ~6 s/ledger.
pub const CREDIT_LINE_TTL_THRESHOLD: u32 = 14_400;

/// Target TTL to extend credit-line persistent entries to on every interaction.
/// Approximately 30 days at the Stellar Mainnet rate of ~6 s/ledger.
pub const CREDIT_LINE_TTL_EXTEND_TO: u32 = 432_000;

pub fn admin_key(env: &Env) -> Symbol {
    Symbol::new(env, "admin")
}

pub fn reentrancy_key(env: &Env) -> Symbol {
    Symbol::new(env, "reentrancy")
}

pub fn rate_cfg_key(env: &Env) -> Symbol {
    Symbol::new(env, "rate_cfg")
}

/// Assert reentrancy guard is not set; set it for the duration of the call.
/// Caller must call clear_reentrancy_guard when done (on all paths).
pub fn set_reentrancy_guard(env: &Env) {
    let key = reentrancy_key(env);
    let current: bool = env.storage().instance().get(&key).unwrap_or(false);
    if current {
        panic!("reentrancy guard");
    }
    env.storage().instance().set(&key, &true);
}

pub fn clear_reentrancy_guard(env: &Env) {
    env.storage().instance().set(&reentrancy_key(env), &false);
}
