// SPDX-License-Identifier: Apache-2.0
//! One-shot baseline regenerator.
//!
//! Run with:
//! ```
//! cargo run --example budget_baseline
//! ```
//!
//! This calls every instrumented entrypoint with the same setups used in
//! `tests/budget_regression.rs`, records the observed budget, and overwrites
//! `contracts/credit/test_snapshots/budget.json`.
//!
//! **Review the diff before committing** — the whole point of the snapshot is
//! to make regressions visible.

use soroban_sdk::{testutils::Budget, token, Address, Env};
use std::{io::Write, path::Path};

#[derive(Debug, serde::Serialize)]
struct Baseline {
    entrypoint: &'static str,
    cpu_instructions: u64,
    memory_bytes: u64,
    tolerance_pct: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    _comment: Option<&'static str>,
}

/// Tiny helper: reset budget, run closure, return (cpu, mem).
fn measure(env: &Env, f: impl FnOnce()) -> (u64, u64) {
    env.budget().reset_unlimited();
    f();
    (
        env.budget().cpu_instruction_count(),
        env.budget().memory_bytes_count(),
    )
}

fn setup() -> (
    Env,
    credit::CreditClient<'static>,
    token::StellarAssetClient<'static>,
    Address,
    Address,
) {
    let env = Env::default();
    env.budget().reset_unlimited();

    let admin = Address::generate(&env);
    let borrower = Address::generate(&env);

    let token_id = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    let token = token::StellarAssetClient::new(&env, &token_id);
    token.mint(&admin, &1_000_000_000_i128);
    token.mint(&borrower, &500_000_000_i128);

    let credit_id = env.register(credit::Credit, ());
    let credit = credit::CreditClient::new(&env, &credit_id);

    env.mock_all_auths();
    credit.init(&admin);
    credit.set_liquidity_token(&token_id);
    credit.set_liquidity_source(&admin);

    (env, credit, token, admin, borrower)
}

fn main() {
    let mut results: Vec<Baseline> = Vec::new();

    // ── init ─────────────────────────────────────────────────────────────────
    {
        let env = Env::default();
        env.budget().reset_unlimited();
        let admin = Address::generate(&env);
        let credit_id = env.register(credit::Credit, ());
        let credit = credit::CreditClient::new(&env, &credit_id);
        env.mock_all_auths();
        let (cpu, mem) = measure(&env, || credit.init(&admin));
        results.push(Baseline {
            entrypoint: "init",
            cpu_instructions: cpu,
            memory_bytes: mem,
            tolerance_pct: 5.0,
            _comment: None,
        });
        eprintln!("init  cpu={cpu}  mem={mem}");
    }

    // ── open_credit_line ─────────────────────────────────────────────────────
    {
        let (env, credit, _tok, _adm, borrower) = setup();
        let (cpu, mem) = measure(&env, || {
            credit.open_credit_line(&borrower, &1_000_000_i128, &500_u32);
        });
        results.push(Baseline {
            entrypoint: "open_credit_line",
            cpu_instructions: cpu,
            memory_bytes: mem,
            tolerance_pct: 5.0,
            _comment: None,
        });
        eprintln!("open_credit_line  cpu={cpu}  mem={mem}");
    }

    // ── draw_credit ──────────────────────────────────────────────────────────
    {
        let (env, credit, token, admin, borrower) = setup();
        credit.open_credit_line(&borrower, &1_000_000_i128, &500_u32);
        token.approve(&admin, &credit.address, &1_000_000_i128, &1000_u32);
        let (cpu, mem) = measure(&env, || {
            credit.draw_credit(&borrower, &100_000_i128);
        });
        results.push(Baseline {
            entrypoint: "draw_credit",
            cpu_instructions: cpu,
            memory_bytes: mem,
            tolerance_pct: 5.0,
            _comment: None,
        });
        eprintln!("draw_credit  cpu={cpu}  mem={mem}");
    }

    // ── repay_credit ─────────────────────────────────────────────────────────
    {
        let (env, credit, token, admin, borrower) = setup();
        credit.open_credit_line(&borrower, &1_000_000_i128, &500_u32);
        token.approve(&admin, &credit.address, &1_000_000_i128, &1000_u32);
        credit.draw_credit(&borrower, &100_000_i128);
        token.approve(&borrower, &credit.address, &200_000_i128, &1000_u32);
        let (cpu, mem) = measure(&env, || {
            credit.repay_credit(&borrower, &50_000_i128);
        });
        results.push(Baseline {
            entrypoint: "repay_credit",
            cpu_instructions: cpu,
            memory_bytes: mem,
            tolerance_pct: 5.0,
            _comment: None,
        });
        eprintln!("repay_credit  cpu={cpu}  mem={mem}");
    }

    // ── update_risk_parameters ───────────────────────────────────────────────
    {
        let (env, credit, _tok, _adm, borrower) = setup();
        credit.open_credit_line(&borrower, &1_000_000_i128, &500_u32);
        let (cpu, mem) = measure(&env, || {
            credit.update_risk_parameters(&borrower, &400_u32, &900_000_i128);
        });
        results.push(Baseline {
            entrypoint: "update_risk_parameters",
            cpu_instructions: cpu,
            memory_bytes: mem,
            tolerance_pct: 5.0,
            _comment: None,
        });
        eprintln!("update_risk_parameters  cpu={cpu}  mem={mem}");
    }

    // ── set_rate_formula_config ──────────────────────────────────────────────
    {
        let (env, credit, ..) = setup();
        let (cpu, mem) = measure(&env, || {
            credit.set_rate_formula_config(&200_u32, &10_u32, &100_u32, &2_000_u32);
        });
        results.push(Baseline {
            entrypoint: "set_rate_formula_config",
            cpu_instructions: cpu,
            memory_bytes: mem,
            tolerance_pct: 5.0,
            _comment: None,
        });
        eprintln!("set_rate_formula_config  cpu={cpu}  mem={mem}");
    }

    // ── set_credit_limit_bounds ──────────────────────────────────────────────
    {
        let (env, credit, ..) = setup();
        let (cpu, mem) = measure(&env, || {
            credit.set_credit_limit_bounds(&10_000_i128, &50_000_000_i128);
        });
        results.push(Baseline {
            entrypoint: "set_credit_limit_bounds",
            cpu_instructions: cpu,
            memory_bytes: mem,
            tolerance_pct: 5.0,
            _comment: None,
        });
        eprintln!("set_credit_limit_bounds  cpu={cpu}  mem={mem}");
    }

    // ── set_utilization_cap ──────────────────────────────────────────────────
    {
        let (env, credit, ..) = setup();
        let (cpu, mem) = measure(&env, || {
            credit.set_utilization_cap(&8_000_u32);
        });
        results.push(Baseline {
            entrypoint: "set_utilization_cap",
            cpu_instructions: cpu,
            memory_bytes: mem,
            tolerance_pct: 5.0,
            _comment: None,
        });
        eprintln!("set_utilization_cap  cpu={cpu}  mem={mem}");
    }

    // ── deposit_collateral ───────────────────────────────────────────────────
    {
        let (env, credit, token, _adm, borrower) = setup();
        credit.open_credit_line(&borrower, &1_000_000_i128, &500_u32);
        token.approve(&borrower, &credit.address, &200_000_i128, &1000_u32);
        let (cpu, mem) = measure(&env, || {
            credit.deposit_collateral(&borrower, &100_000_i128);
        });
        results.push(Baseline {
            entrypoint: "deposit_collateral",
            cpu_instructions: cpu,
            memory_bytes: mem,
            tolerance_pct: 5.0,
            _comment: None,
        });
        eprintln!("deposit_collateral  cpu={cpu}  mem={mem}");
    }

    // ── withdraw_collateral ──────────────────────────────────────────────────
    {
        let (env, credit, token, _adm, borrower) = setup();
        credit.open_credit_line(&borrower, &1_000_000_i128, &500_u32);
        token.approve(&borrower, &credit.address, &200_000_i128, &1000_u32);
        credit.deposit_collateral(&borrower, &100_000_i128);
        let (cpu, mem) = measure(&env, || {
            credit.withdraw_collateral(&borrower, &50_000_i128);
        });
        results.push(Baseline {
            entrypoint: "withdraw_collateral",
            cpu_instructions: cpu,
            memory_bytes: mem,
            tolerance_pct: 5.0,
            _comment: None,
        });
        eprintln!("withdraw_collateral  cpu={cpu}  mem={mem}");
    }

    // ── accrue_batch (empty list — zero-cost floor) ───────────────────────────
    {
        let (env, credit, ..) = setup();
        let empty = soroban_sdk::Vec::new(&env);
        let (cpu, mem) = measure(&env, || {
            credit.accrue_batch(&empty);
        });
        results.push(Baseline {
            entrypoint: "accrue_batch",
            cpu_instructions: cpu,
            memory_bytes: mem,
            tolerance_pct: 10.0,
            _comment: Some(
                "Batch size varies; wider tolerance applied. Regenerate with a fixed 5-borrower batch.",
            ),
        });
        eprintln!("accrue_batch  cpu={cpu}  mem={mem}");
    }

    // ── pause_protocol ────────────────────────────────────────────────────────
    {
        let (env, credit, ..) = setup();
        let (cpu, mem) = measure(&env, || {
            credit.pause_protocol();
        });
        results.push(Baseline {
            entrypoint: "pause_protocol",
            cpu_instructions: cpu,
            memory_bytes: mem,
            tolerance_pct: 5.0,
            _comment: None,
        });
        eprintln!("pause_protocol  cpu={cpu}  mem={mem}");
    }

    // ── unpause_protocol ──────────────────────────────────────────────────────
    {
        let (env, credit, ..) = setup();
        credit.pause_protocol();
        let (cpu, mem) = measure(&env, || {
            credit.unpause_protocol();
        });
        results.push(Baseline {
            entrypoint: "unpause_protocol",
            cpu_instructions: cpu,
            memory_bytes: mem,
            tolerance_pct: 5.0,
            _comment: None,
        });
        eprintln!("unpause_protocol  cpu={cpu}  mem={mem}");
    }

    // ── default_credit_line ───────────────────────────────────────────────────
    {
        let (env, credit, token, admin, borrower) = setup();
        credit.open_credit_line(&borrower, &1_000_000_i128, &500_u32);
        token.approve(&admin, &credit.address, &1_000_000_i128, &1000_u32);
        credit.draw_credit(&borrower, &500_000_i128);
        env.ledger().with_mut(|l| l.timestamp += 86_400 * 120);
        let (cpu, mem) = measure(&env, || {
            credit.default_credit_line(&borrower);
        });
        results.push(Baseline {
            entrypoint: "default_credit_line",
            cpu_instructions: cpu,
            memory_bytes: mem,
            tolerance_pct: 5.0,
            _comment: None,
        });
        eprintln!("default_credit_line  cpu={cpu}  mem={mem}");
    }

    // ── close_credit_line ─────────────────────────────────────────────────────
    {
        let (env, credit, _tok, _adm, borrower) = setup();
        credit.open_credit_line(&borrower, &1_000_000_i128, &500_u32);
        let (cpu, mem) = measure(&env, || {
            credit.close_credit_line(&borrower);
        });
        results.push(Baseline {
            entrypoint: "close_credit_line",
            cpu_instructions: cpu,
            memory_bytes: mem,
            tolerance_pct: 5.0,
            _comment: None,
        });
        eprintln!("close_credit_line  cpu={cpu}  mem={mem}");
    }

    // ── write output ─────────────────────────────────────────────────────────
    let out_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("test_snapshots")
        .join("budget.json");

    std::fs::create_dir_all(out_path.parent().unwrap()).unwrap();

    let json = serde_json::to_string_pretty(&results).expect("serialization failed");
    let mut file = std::fs::File::create(&out_path)
        .unwrap_or_else(|e| panic!("cannot create {}: {e}", out_path.display()));
    writeln!(file, "{json}").unwrap();

    eprintln!(
        "\n✓  Wrote {} baselines to {}",
        results.len(),
        out_path.display()
    );
}
