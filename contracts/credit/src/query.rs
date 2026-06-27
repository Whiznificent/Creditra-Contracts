use crate::storage::{CREDIT_LINE_TTL_EXTEND_TO, CREDIT_LINE_TTL_THRESHOLD};
use crate::types::CreditLineData;
use soroban_sdk::{Address, Env};

pub fn get_credit_line(env: Env, borrower: Address) -> Option<CreditLineData> {
    let result: Option<CreditLineData> = env.storage().persistent().get(&borrower);
    if result.is_some() {
        env.storage()
            .persistent()
            .extend_ttl(&borrower, CREDIT_LINE_TTL_THRESHOLD, CREDIT_LINE_TTL_EXTEND_TO);
    }
    result
}
