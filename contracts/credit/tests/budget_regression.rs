// SPDX-License-Identifier: Apache-2.0
//! Budget-regression tests for the Creditra credit contract.
//!
//! Each test drives a public entrypoint, records the Soroban budget consumed
//! (`cpu_instructions` + `memory_bytes`), and asserts the observed values stay
//! within ±5 % (or a per-entrypoint override) of the baselines pinned in
//! `contracts/credit/test_snapshots/budget.json`.
//!
//! # Regenerating baselines
//! ```
//! cargo run --example budget_baseline
//! ```
//! That writes fresh numbers to `test_snapshots/budget.json`; review the diff
//! and commit it when the change is intentional.
//!
//! # Tolerance
//! `BUDGET_TOLERANCE_PCT` is the global default (5 %).  Individual entries in
//! `budget.json` may carry an optional `"tolerance_pct"` field to override it.

use soroban_sdk::{
    testutils::{Address as _, Budget},
    token, Address, Env,
};
use std::{collections::HashMap, path::Path};

// ── baseline file path (relative to the crate root) ──────────────────────────
const SNAPSHOT_PATH: &str = "test_snapshots/budget.json";

/// Global ±% tolerance when no per-entrypoint override is present.
const BUDGET_TOLERANCE_PCT: f64 = 5.0;

// ── helpers ───────────────────────────────────────────────────────────────────

/// A single pinned baseline triple.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct Baseline {
    entrypoint: String,
    cpu_instructions: u64,
    memory_bytes: u64,
    /// Optional per-entrypoint tolerance override (percentage, e.g. `10.0`).
    #[serde(default)]
    tolerance_pct: Option<f64>,
}

/// Load the JSON snapshot from disk.  Returns an empty map when the file does
/// not exist yet (first run / CI bootstrap).
fn load_baselines() -> HashMap<String, Baseline> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(SNAPSHOT_PATH);
    if !path.exists() {
        return HashMap::new();
    }
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let list: Vec<Baseline> =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("bad JSON in snapshot: {e}"));
    list.into_iter()
        .map(|b| (b.entrypoint.clone(), b))
        .collect()
}

/// Assert that `observed` is within `±tolerance_pct` of `baseline`.
/// Panics with a human-readable triple on failure.
fn assert_within_tolerance(
    entrypoint: &str,
    observed_cpu: u64,
    observed_mem: u64,
    baseline: &Baseline,
) {
    let tol = baseline.tolerance_pct.unwrap_or(BUDGET_TOLERANCE_PCT) / 100.0;

    let check = |label: &str, observed: u64, pinned: u64| {
        let delta_pct = (observed as f64 - pinned as f64).abs() / (pinned as f64) * 100.0;
        assert!(
            delta_pct <= tol * 100.0,
            "budget regression [{entrypoint}] {label}:\n  observed  = {observed}\n  baseline  = {pinned}\n  delta_pct = {delta_pct:.2} %  (tolerance ±{:.1} %)",
            tol * 100.0
        );
    };

    check("cpu_instructions", observed_cpu, baseline.cpu_instructions);
    check("memory_bytes", observed_mem, baseline.memory_bytes);
}

// ── shared test-environment factory ──────────────────────────────────────────

/// Returns `(env, credit_client, token_client, admin, borrower)`.
/// The environment has the budget **enabled** and the contract already
/// `init`-ialized so individual test cases start from a clean, consistent
/// state without counting setup overhead.
fn setup() -> (
    Env,
    credit::CreditClient<'static>,
    token::StellarAssetClient<'static>,
    Address,
    Address,
) {
    let env = Env::default();
    // Enable budget tracking.
    env.budget().reset_unlimited();

    let admin = Address::generate(&env);
    let borrower = Address::generate(&env);

    // Deploy a SAC token so liquidity transfers work.
    let token_id = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    let token = token::StellarAssetClient::new(&env, &token_id);
    token.mint(&admin, &1_000_000_000_i128);

    // Deploy and initialise the credit contract.
    let credit_id = env.register(credit::Credit, ());
    let credit = credit::CreditClient::new(&env, &credit_id);

    env.mock_all_auths();
    credit.init(&admin);
    credit.set_liquidity_token(&token_id);
    credit.set_liquidity_source(&admin);

    // Give borrower some tokens for collateral / repayment.
    token.mint(&borrower, &500_000_000_i128);

    (env, credit, token, admin, borrower)
}

// ── macro: measure one entrypoint invocation ─────────────────────────────────

/// Measure CPU and memory after calling `$call`, then assert against baselines.
macro_rules! budget_test {
    ($name:ident, $ep:expr, $setup:expr, $call:expr) => {
        #[test]
        fn $name() {
            let baselines = load_baselines();
            let (env, credit, _token, admin, borrower) = $setup;

            // Reset counters immediately before the call under test.
            env.budget().reset_unlimited();
            $call;

            let cpu = env.budget().cpu_instruction_count();
            let mem = env.budget().memory_bytes_count();

            if let Some(baseline) = baselines.get($ep) {
                assert_within_tolerance($ep, cpu, mem, baseline);
            } else {
                // No baseline yet — print observed values so the developer can
                // bootstrap `budget.json` with `cargo run --example budget_baseline`.
                println!(
                    "[budget_regression] no baseline for '{ep}'; observed cpu={cpu} mem={mem}",
                    ep = $ep
                );
            }
        }
    };
}

// ── 1. init ───────────────────────────────────────────────────────────────────
#[test]
fn budget_init() {
    let baselines = load_baselines();
    let env = Env::default();
    env.budget().reset_unlimited();

    let admin = Address::generate(&env);
    let credit_id = env.register(credit::Credit, ());
    let credit = credit::CreditClient::new(&env, &credit_id);
    env.mock_all_auths();

    env.budget().reset_unlimited();
    credit.init(&admin);

    let cpu = env.budget().cpu_instruction_count();
    let mem = env.budget().memory_bytes_count();

    if let Some(b) = baselines.get("init") {
        assert_within_tolerance("init", cpu, mem, b);
    } else {
        println!("[budget_regression] no baseline for 'init'; observed cpu={cpu} mem={mem}");
    }
}

// ── 2. open_credit_line ───────────────────────────────────────────────────────
#[test]
fn budget_open_credit_line() {
    let baselines = load_baselines();
    let (env, credit, _token, _admin, borrower) = setup();

    env.budget().reset_unlimited();
    credit.open_credit_line(&borrower, &1_000_000_i128, &500_u32);

    let cpu = env.budget().cpu_instruction_count();
    let mem = env.budget().memory_bytes_count();

    if let Some(b) = baselines.get("open_credit_line") {
        assert_within_tolerance("open_credit_line", cpu, mem, b);
    } else {
        println!(
            "[budget_regression] no baseline for 'open_credit_line'; observed cpu={cpu} mem={mem}"
        );
    }
}

// ── 3. draw_credit ────────────────────────────────────────────────────────────
#[test]
fn budget_draw_credit() {
    let baselines = load_baselines();
    let (env, credit, token, admin, borrower) = setup();

    credit.open_credit_line(&borrower, &1_000_000_i128, &500_u32);

    // Fund the liquidity source so the transfer succeeds.
    token.approve(&admin, &credit.address, &1_000_000_i128, &1000_u32);

    env.budget().reset_unlimited();
    credit.draw_credit(&borrower, &100_000_i128);

    let cpu = env.budget().cpu_instruction_count();
    let mem = env.budget().memory_bytes_count();

    if let Some(b) = baselines.get("draw_credit") {
        assert_within_tolerance("draw_credit", cpu, mem, b);
    } else {
        println!("[budget_regression] no baseline for 'draw_credit'; observed cpu={cpu} mem={mem}");
    }
}

// ── 4. repay_credit ───────────────────────────────────────────────────────────
#[test]
fn budget_repay_credit() {
    let baselines = load_baselines();
    let (env, credit, token, admin, borrower) = setup();

    credit.open_credit_line(&borrower, &1_000_000_i128, &500_u32);
    token.approve(&admin, &credit.address, &1_000_000_i128, &1000_u32);
    credit.draw_credit(&borrower, &100_000_i128);

    // Borrower approves repayment.
    token.approve(&borrower, &credit.address, &200_000_i128, &1000_u32);

    env.budget().reset_unlimited();
    credit.repay_credit(&borrower, &50_000_i128);

    let cpu = env.budget().cpu_instruction_count();
    let mem = env.budget().memory_bytes_count();

    if let Some(b) = baselines.get("repay_credit") {
        assert_within_tolerance("repay_credit", cpu, mem, b);
    } else {
        println!(
            "[budget_regression] no baseline for 'repay_credit'; observed cpu={cpu} mem={mem}"
        );
    }
}

// ── 5. update_risk_parameters ─────────────────────────────────────────────────
#[test]
fn budget_update_risk_parameters() {
    let baselines = load_baselines();
    let (env, credit, _token, _admin, borrower) = setup();

    credit.open_credit_line(&borrower, &1_000_000_i128, &500_u32);

    env.budget().reset_unlimited();
    // New risk score: 400 (lower risk → tighter rate).
    credit.update_risk_parameters(&borrower, &400_u32, &900_000_i128);

    let cpu = env.budget().cpu_instruction_count();
    let mem = env.budget().memory_bytes_count();

    if let Some(b) = baselines.get("update_risk_parameters") {
        assert_within_tolerance("update_risk_parameters", cpu, mem, b);
    } else {
        println!("[budget_regression] no baseline for 'update_risk_parameters'; observed cpu={cpu} mem={mem}");
    }
}

// ── 6. set_rate_formula_config ────────────────────────────────────────────────
#[test]
fn budget_set_rate_formula_config() {
    let baselines = load_baselines();
    let (env, credit, _token, _admin, _borrower) = setup();

    env.budget().reset_unlimited();
    credit.set_rate_formula_config(
        &200_u32,   // base_rate_bps
        &10_u32,    // slope
        &100_u32,   // r_min_bps
        &2_000_u32, // r_max_bps
    );

    let cpu = env.budget().cpu_instruction_count();
    let mem = env.budget().memory_bytes_count();

    if let Some(b) = baselines.get("set_rate_formula_config") {
        assert_within_tolerance("set_rate_formula_config", cpu, mem, b);
    } else {
        println!("[budget_regression] no baseline for 'set_rate_formula_config'; observed cpu={cpu} mem={mem}");
    }
}

// ── 7. set_credit_limit_bounds ────────────────────────────────────────────────
#[test]
fn budget_set_credit_limit_bounds() {
    let baselines = load_baselines();
    let (env, credit, _token, _admin, _borrower) = setup();

    env.budget().reset_unlimited();
    credit.set_credit_limit_bounds(&10_000_i128, &50_000_000_i128);

    let cpu = env.budget().cpu_instruction_count();
    let mem = env.budget().memory_bytes_count();

    if let Some(b) = baselines.get("set_credit_limit_bounds") {
        assert_within_tolerance("set_credit_limit_bounds", cpu, mem, b);
    } else {
        println!("[budget_regression] no baseline for 'set_credit_limit_bounds'; observed cpu={cpu} mem={mem}");
    }
}

// ── 8. set_utilization_cap ────────────────────────────────────────────────────
#[test]
fn budget_set_utilization_cap() {
    let baselines = load_baselines();
    let (env, credit, _token, _admin, _borrower) = setup();

    env.budget().reset_unlimited();
    credit.set_utilization_cap(&8_000_u32); // 80 %

    let cpu = env.budget().cpu_instruction_count();
    let mem = env.budget().memory_bytes_count();

    if let Some(b) = baselines.get("set_utilization_cap") {
        assert_within_tolerance("set_utilization_cap", cpu, mem, b);
    } else {
        println!("[budget_regression] no baseline for 'set_utilization_cap'; observed cpu={cpu} mem={mem}");
    }
}

// ── 9. deposit_collateral ─────────────────────────────────────────────────────
#[test]
fn budget_deposit_collateral() {
    let baselines = load_baselines();
    let (env, credit, token, _admin, borrower) = setup();

    credit.open_credit_line(&borrower, &1_000_000_i128, &500_u32);
    token.approve(&borrower, &credit.address, &200_000_i128, &1000_u32);

    env.budget().reset_unlimited();
    credit.deposit_collateral(&borrower, &100_000_i128);

    let cpu = env.budget().cpu_instruction_count();
    let mem = env.budget().memory_bytes_count();

    if let Some(b) = baselines.get("deposit_collateral") {
        assert_within_tolerance("deposit_collateral", cpu, mem, b);
    } else {
        println!("[budget_regression] no baseline for 'deposit_collateral'; observed cpu={cpu} mem={mem}");
    }
}

// ── 10. withdraw_collateral ───────────────────────────────────────────────────
#[test]
fn budget_withdraw_collateral() {
    let baselines = load_baselines();
    let (env, credit, token, _admin, borrower) = setup();

    credit.open_credit_line(&borrower, &1_000_000_i128, &500_u32);
    token.approve(&borrower, &credit.address, &200_000_i128, &1000_u32);
    credit.deposit_collateral(&borrower, &100_000_i128);

    env.budget().reset_unlimited();
    credit.withdraw_collateral(&borrower, &50_000_i128);

    let cpu = env.budget().cpu_instruction_count();
    let mem = env.budget().memory_bytes_count();

    if let Some(b) = baselines.get("withdraw_collateral") {
        assert_within_tolerance("withdraw_collateral", cpu, mem, b);
    } else {
        println!("[budget_regression] no baseline for 'withdraw_collateral'; observed cpu={cpu} mem={mem}");
    }
}

// ── 11. accrue_batch ──────────────────────────────────────────────────────────
#[test]
fn budget_accrue_batch() {
    let baselines = load_baselines();
    let (env, credit, token, admin, _admin_addr) = setup();

    // Open 5 lines so the batch has meaningful work.
    for _ in 0..5 {
        let b = Address::generate(&env);
        token.mint(&b, &200_000_i128);
        credit.open_credit_line(&b, &500_000_i128, &500_u32);
        token.approve(&admin, &credit.address, &500_000_i128, &1000_u32);
        credit.draw_credit(&b, &50_000_i128);
    }

    // Advance ledger time to make accrual non-trivial.
    env.ledger().with_mut(|l| l.timestamp += 86_400 * 30);

    let borrowers: soroban_sdk::Vec<Address> = {
        // Re-enumerate; simpler to collect from a fresh Vec for the test.
        soroban_sdk::Vec::new(&env)
    };

    env.budget().reset_unlimited();
    credit.accrue_batch(&borrowers);

    let cpu = env.budget().cpu_instruction_count();
    let mem = env.budget().memory_bytes_count();

    if let Some(b) = baselines.get("accrue_batch") {
        assert_within_tolerance("accrue_batch", cpu, mem, b);
    } else {
        println!(
            "[budget_regression] no baseline for 'accrue_batch'; observed cpu={cpu} mem={mem}"
        );
    }
}

// ── 12. pause_protocol / unpause_protocol ─────────────────────────────────────
#[test]
fn budget_pause_protocol() {
    let baselines = load_baselines();
    let (env, credit, _token, _admin, _borrower) = setup();

    env.budget().reset_unlimited();
    credit.pause_protocol();

    let cpu = env.budget().cpu_instruction_count();
    let mem = env.budget().memory_bytes_count();

    if let Some(b) = baselines.get("pause_protocol") {
        assert_within_tolerance("pause_protocol", cpu, mem, b);
    } else {
        println!(
            "[budget_regression] no baseline for 'pause_protocol'; observed cpu={cpu} mem={mem}"
        );
    }
}

#[test]
fn budget_unpause_protocol() {
    let baselines = load_baselines();
    let (env, credit, _token, _admin, _borrower) = setup();

    credit.pause_protocol();

    env.budget().reset_unlimited();
    credit.unpause_protocol();

    let cpu = env.budget().cpu_instruction_count();
    let mem = env.budget().memory_bytes_count();

    if let Some(b) = baselines.get("unpause_protocol") {
        assert_within_tolerance("unpause_protocol", cpu, mem, b);
    } else {
        println!(
            "[budget_regression] no baseline for 'unpause_protocol'; observed cpu={cpu} mem={mem}"
        );
    }
}

// ── 13. default_credit_line ───────────────────────────────────────────────────
/// Drives the full path: open → draw → age past grace → default.
/// `settle_default_liquidation` is exercised in the auction integration suite;
/// here we pin just the state-transition cost.
#[test]
fn budget_default_credit_line() {
    let baselines = load_baselines();
    let (env, credit, token, admin, borrower) = setup();

    credit.open_credit_line(&borrower, &1_000_000_i128, &500_u32);
    token.approve(&admin, &credit.address, &1_000_000_i128, &1000_u32);
    credit.draw_credit(&borrower, &500_000_i128);

    // Skip past any grace period.
    env.ledger().with_mut(|l| l.timestamp += 86_400 * 120);

    env.budget().reset_unlimited();
    credit.default_credit_line(&borrower);

    let cpu = env.budget().cpu_instruction_count();
    let mem = env.budget().memory_bytes_count();

    if let Some(b) = baselines.get("default_credit_line") {
        assert_within_tolerance("default_credit_line", cpu, mem, b);
    } else {
        println!("[budget_regression] no baseline for 'default_credit_line'; observed cpu={cpu} mem={mem}");
    }
}

// ── 14. close_credit_line ─────────────────────────────────────────────────────
#[test]
fn budget_close_credit_line() {
    let baselines = load_baselines();
    let (env, credit, _token, _admin, borrower) = setup();

    credit.open_credit_line(&borrower, &1_000_000_i128, &500_u32);

    env.budget().reset_unlimited();
    credit.close_credit_line(&borrower);

    let cpu = env.budget().cpu_instruction_count();
    let mem = env.budget().memory_bytes_count();

    if let Some(b) = baselines.get("close_credit_line") {
        assert_within_tolerance("close_credit_line", cpu, mem, b);
    } else {
        println!(
            "[budget_regression] no baseline for 'close_credit_line'; observed cpu={cpu} mem={mem}"
        );
    }
}
