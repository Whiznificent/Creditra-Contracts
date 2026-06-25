// SPDX-License-Identifier: MIT

//! Storage-schema migration runner.
//!
//! Migrations are keyed by the version they migrate **from**. For example, the
//! migration registered at `0` upgrades storage from version 0 to version 1.
//! Keeping each step small and idempotent makes a failed transaction safe to
//! retry and keeps future schema bumps reviewable.

use crate::events::{publish_schema_version_event, SchemaVersionEvent};
use crate::storage::{get_schema_version, set_schema_version, DataKey};
use soroban_sdk::Env;

type Migration = fn(&Env);

/// Run all registered storage up-migrations until storage reaches the compiled
/// target [`crate::SCHEMA_VERSION`].
///
/// The caller is authenticated by the public `migrate_storage` entrypoint in
/// `lib.rs`; this function contains only deterministic storage transitions.
pub fn migrate_storage(env: &Env) {
    let from = get_schema_version(env).unwrap_or(0);
    let target = crate::SCHEMA_VERSION;

    if from == target {
        return;
    }
    if from > target {
        panic!("stored schema version is newer than this contract");
    }

    let mut current = from;
    while current < target {
        let migration = migration_for(current).unwrap_or_else(|| {
            panic!("missing storage migration");
        });
        migration(env);
        current = current.saturating_add(1);
    }

    set_schema_version(env, target);
    publish_schema_version_event(env, SchemaVersionEvent { from, to: target });
}

fn migration_for(from_version: u32) -> Option<Migration> {
    match from_version {
        0 => Some(migrate_0_to_1),
        _ => None,
    }
}

/// Backfill the v1 global counters introduced at initialization time.
///
/// The checks make the step idempotent: retrying the same migration cannot
/// overwrite live counters that already exist.
fn migrate_0_to_1(env: &Env) {
    if !env.storage().instance().has(&DataKey::CreditLineCount) {
        env.storage()
            .instance()
            .set(&DataKey::CreditLineCount, &0_u32);
    }
    if !env.storage().instance().has(&DataKey::TotalUtilized) {
        env.storage()
            .instance()
            .set(&DataKey::TotalUtilized, &0_i128);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Credit, CreditClient};
    use soroban_sdk::testutils::{Address as _, Events};
    use soroban_sdk::{Address, Env, Symbol, TryFromVal};

    fn setup() -> (Env, Address, CreditClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);
        client.init(&admin);

        (env, contract_id, client)
    }

    #[test]
    fn migrate_storage_noops_when_already_at_target_version() {
        let (env, _contract_id, client) = setup();
        let before_events = env.events().all().len();

        client.migrate_storage();

        assert_eq!(client.get_schema_version(), Some(crate::SCHEMA_VERSION));
        assert_eq!(env.events().all().len(), before_events);
    }

    #[test]
    fn migrate_storage_runs_up_migration_and_emits_event() {
        let (env, contract_id, client) = setup();

        env.as_contract(&contract_id, || {
            env.storage().instance().remove(&DataKey::SchemaVersion);
            env.storage().instance().remove(&DataKey::CreditLineCount);
            env.storage().instance().remove(&DataKey::TotalUtilized);
        });

        client.migrate_storage();

        assert_eq!(client.get_schema_version(), Some(crate::SCHEMA_VERSION));
        env.as_contract(&contract_id, || {
            let count: u32 = env
                .storage()
                .instance()
                .get(&DataKey::CreditLineCount)
                .unwrap();
            let total: i128 = env
                .storage()
                .instance()
                .get(&DataKey::TotalUtilized)
                .unwrap();
            assert_eq!(count, 0);
            assert_eq!(total, 0);
        });

        let events = env.events().all();
        let last = events.get(events.len() - 1).unwrap();
        let topics = last.1;
        assert_eq!(topics.get(0).unwrap(), Symbol::new(&env, "credit"));
        assert_eq!(topics.get(1).unwrap(), Symbol::new(&env, "schema_v"));

        let event = SchemaVersionEvent::try_from_val(&env, &last.2).unwrap();
        assert_eq!(event, SchemaVersionEvent { from: 0, to: 1 });
    }

    #[test]
    fn migrate_storage_preserves_existing_v1_counters() {
        let (env, contract_id, client) = setup();

        env.as_contract(&contract_id, || {
            env.storage().instance().remove(&DataKey::SchemaVersion);
            env.storage()
                .instance()
                .set(&DataKey::CreditLineCount, &7_u32);
            env.storage()
                .instance()
                .set(&DataKey::TotalUtilized, &123_i128);
        });

        client.migrate_storage();

        env.as_contract(&contract_id, || {
            let count: u32 = env
                .storage()
                .instance()
                .get(&DataKey::CreditLineCount)
                .unwrap();
            let total: i128 = env
                .storage()
                .instance()
                .get(&DataKey::TotalUtilized)
                .unwrap();
            assert_eq!(count, 7);
            assert_eq!(total, 123);
        });
    }

    #[test]
    fn migrate_storage_requires_admin_auth() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let contract_id = env.register(Credit, ());
        let client = CreditClient::new(&env, &contract_id);

        client.init(&admin);

        let result = client.try_migrate_storage();
        assert!(result.is_err());
    }
}
