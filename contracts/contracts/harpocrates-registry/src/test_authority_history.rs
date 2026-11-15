#![cfg(test)]

use crate::{
    HarpocratesRegistry, HarpocratesRegistryClient, RegistryError, AUTH_HIST_ADMIN_ACCEPTED,
    AUTH_HIST_ADMIN_CANCELLED, AUTH_HIST_ADMIN_PROPOSED, AUTH_HIST_COUNCIL_EXEC,
    AUTH_HIST_COUNCIL_SET, AUTH_HIST_GUARDIAN_CLEARED, AUTH_HIST_GUARDIAN_SET, AUTH_HIST_INIT,
    AUTH_HIST_ISSUER_ADDED, AUTH_HIST_ISSUER_GRACE_END, AUTH_HIST_ISSUER_REVOKED,
    AUTH_HIST_ISSUER_ROTATED, AUTH_HIST_SEAL_POLICY_CANCEL, AUTH_HIST_SEAL_POLICY_SET,
    MAX_AUTHORITY_HISTORY_ENTRIES, MAX_AUTHORITY_HISTORY_PAGE,
};
use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
    Address, BytesN, Env, Vec,
};

fn setup() -> (Env, HarpocratesRegistryClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_700_000_000);
    env.ledger().set_sequence_number(100);
    let id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &id);
    let admin = Address::generate(&env);
    (env, client, admin)
}

#[test]
fn empty_before_init_and_invalid_limits_rejected() {
    let (_env, client, _admin) = setup();

    assert_eq!(client.get_authority_history_count(), 0);
    assert_eq!(client.get_authority_history_at(&0), None);
    assert_eq!(client.get_authority_history_at(&1), None);

    let page = client.list_authority_history(&0, &10);
    assert_eq!(page.entries.len(), 0);
    assert_eq!(page.next_cursor, None);
    assert_eq!(page.earliest_seq, 0);
    assert_eq!(page.latest_seq, 0);

    let zero_err = client.try_list_authority_history(&0, &0);
    assert_eq!(
        zero_err,
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::ListLimitExceeded as u32
        )))
    );

    let over_err = client.try_list_authority_history(&0, &(MAX_AUTHORITY_HISTORY_PAGE + 1));
    assert_eq!(
        over_err,
        Err(Ok(soroban_sdk::Error::from_contract_error(
            RegistryError::ListLimitExceeded as u32
        )))
    );
}

#[test]
fn records_stable_role_transitions_with_ledger_timestamps_and_pagination() {
    let (env, client, admin) = setup();
    let issuer_a = Address::generate(&env);
    let issuer_b = Address::generate(&env);
    let guardian = Address::generate(&env);
    let admin_2 = Address::generate(&env);
    let meta = BytesN::from_array(&env, &[0x11; 32]);

    client.init(&admin);

    env.ledger().set_timestamp(1_700_000_100);
    env.ledger().set_sequence_number(101);
    client.add_issuer(&admin, &issuer_a, &meta);
    client.add_issuer(&admin, &issuer_b, &meta);

    env.ledger().set_timestamp(1_700_000_200);
    env.ledger().set_sequence_number(102);
    client.set_guardian(&admin, &guardian);
    client.clear_guardian(&admin);

    env.ledger().set_timestamp(1_700_000_300);
    env.ledger().set_sequence_number(103);
    let grace_end = client.rotate_issuer(&admin, &issuer_a, &issuer_b, &60);
    env.ledger().set_timestamp(grace_end);
    env.ledger().set_sequence_number(104);
    client.finalize_issuer_rotation(&issuer_a);

    env.ledger().set_timestamp(grace_end + 10);
    env.ledger().set_sequence_number(105);
    let pol_ver = client.create_seal_policy(&admin, &2, &3, &3600, &0);
    client.cancel_seal_policy(&admin, &pol_ver);

    env.ledger().set_timestamp(grace_end + 20);
    env.ledger().set_sequence_number(106);
    client.propose_admin(&admin, &admin_2);
    client.cancel_admin_transfer(&admin);
    client.propose_admin(&admin, &admin_2);
    client.accept_admin(&admin_2);

    assert_eq!(client.get_authority_history_count(), 13);

    let first_page = client.list_authority_history(&0, &5);
    assert_eq!(first_page.entries.len(), 5);
    assert_eq!(first_page.earliest_seq, 1);
    assert_eq!(first_page.latest_seq, 13);
    assert_eq!(first_page.next_cursor, Some(6));

    let e1 = first_page.entries.get(0).unwrap();
    assert_eq!(e1.seq, 1);
    assert_eq!(e1.action, AUTH_HIST_INIT);
    assert_eq!(e1.subject, admin);
    assert_eq!(e1.actor, admin);
    assert_eq!(e1.timestamp, 1_700_000_000);
    assert_eq!(e1.ledger_seq, 100);

    let e2 = first_page.entries.get(1).unwrap();
    assert_eq!(e2.seq, 2);
    assert_eq!(e2.action, AUTH_HIST_ISSUER_ADDED);
    assert_eq!(e2.subject, issuer_a);
    assert_eq!(e2.timestamp, 1_700_000_100);
    assert_eq!(e2.ledger_seq, 101);

    let e4 = first_page.entries.get(3).unwrap();
    assert_eq!(e4.action, AUTH_HIST_GUARDIAN_SET);
    assert_eq!(e4.subject, guardian);

    let e5 = first_page.entries.get(4).unwrap();
    assert_eq!(e5.action, AUTH_HIST_GUARDIAN_CLEARED);
    assert_eq!(e5.subject, guardian);

    let second_page = client.list_authority_history(&first_page.next_cursor.unwrap(), &5);
    assert_eq!(second_page.entries.len(), 5);
    assert_eq!(second_page.next_cursor, Some(11));
    assert_eq!(
        second_page.entries.get(0).unwrap().action,
        AUTH_HIST_ISSUER_ROTATED
    );
    assert_eq!(
        second_page.entries.get(1).unwrap().action,
        AUTH_HIST_ISSUER_GRACE_END
    );
    assert_eq!(
        second_page.entries.get(2).unwrap().action,
        AUTH_HIST_SEAL_POLICY_SET
    );
    assert_eq!(second_page.entries.get(2).unwrap().proposal_ref, pol_ver);
    assert_eq!(
        second_page.entries.get(3).unwrap().action,
        AUTH_HIST_SEAL_POLICY_CANCEL
    );
    assert_eq!(
        second_page.entries.get(4).unwrap().action,
        AUTH_HIST_ADMIN_PROPOSED
    );

    let third_page = client.list_authority_history(&second_page.next_cursor.unwrap(), &5);
    assert_eq!(third_page.entries.len(), 3);
    assert_eq!(third_page.next_cursor, None);
    assert_eq!(
        third_page.entries.get(0).unwrap().action,
        AUTH_HIST_ADMIN_CANCELLED
    );
    assert_eq!(
        third_page.entries.get(1).unwrap().action,
        AUTH_HIST_ADMIN_PROPOSED
    );
    assert_eq!(
        third_page.entries.get(2).unwrap().action,
        AUTH_HIST_ADMIN_ACCEPTED
    );
    assert_eq!(third_page.entries.get(2).unwrap().subject, admin_2);

    // Direct lookup by stable sequence number matches paginated entry.
    assert_eq!(
        client.get_authority_history_at(&13),
        Some(third_page.entries.get(2).unwrap())
    );
    // Out-of-range cursor returns an empty slice without reverting.
    let past_end = client.list_authority_history(&99, &5);
    assert_eq!(past_end.entries.len(), 0);
    assert_eq!(past_end.next_cursor, None);
}

#[test]
fn council_transitions_summarize_approver_count_without_historical_approver_iteration() {
    let (env, client, admin) = setup();
    let issuer = Address::generate(&env);
    let verifier = Address::generate(&env);
    let meta = BytesN::from_array(&env, &[0x22; 32]);
    let zero_payload = BytesN::from_array(&env, &[0u8; 32]);

    client.init(&admin);
    client.add_issuer(&admin, &issuer, &meta);

    // Measure single-entry read cost before any council approvals exist.
    env.cost_estimate().budget().reset_unlimited();
    let baseline_page = client.list_authority_history(&2, &1);
    let single_admin_cpu = env.cost_estimate().budget().cpu_instruction_cost();
    assert_eq!(baseline_page.entries.len(), 1);

    // Configure an 8-member council and gather 8 historical approvals on two proposals.
    let mut members = Vec::new(&env);
    let mut member_list = std::vec::Vec::new();
    for _ in 0..8 {
        let m = Address::generate(&env);
        members.push_back(m.clone());
        member_list.push(m);
    }
    client.set_admin_council(&admin, &members, &5);

    // Advance past timelock delay so council becomes active.
    let min_delay = client.get_timelock_min_delay_secs();
    env.ledger().set_timestamp(1_700_000_000 + min_delay + 1);
    env.ledger().set_sequence_number(200);

    // Proposal 1: SetVerifier (action = 1) with 8 approvals.
    let p1 = client.propose_council_action(&member_list[0], &1, &verifier, &zero_payload);
    for m in &member_list {
        client.approve_council_proposal(m, &p1);
    }
    client.execute_council_proposal(&member_list[0], &p1);

    // Proposal 2: RevokeIssuer (action = 2) with 6 approvals.
    let p2 = client.propose_council_action(&member_list[1], &2, &issuer, &zero_payload);
    for m in member_list.iter().take(6) {
        client.approve_council_proposal(m, &p2);
    }
    client.execute_council_proposal(&member_list[1], &p2);

    let council_set = client.get_authority_history_at(&3).unwrap();
    assert_eq!(council_set.action, AUTH_HIST_COUNCIL_SET);
    assert_eq!(council_set.proposal_ref, 5);
    assert_eq!(council_set.approver_count, 8);

    // Measure single-entry read cost on the 8-approver council execution entry.
    env.cost_estimate().budget().reset_unlimited();
    let council_page = client.list_authority_history(&4, &1);
    let council_read_cpu = env.cost_estimate().budget().cpu_instruction_cost();

    let e4 = council_page.entries.get(0).unwrap();
    assert_eq!(e4.action, AUTH_HIST_COUNCIL_EXEC);
    assert_eq!(e4.subject, verifier);
    assert_eq!(e4.proposal_ref, p1);
    assert_eq!(e4.approver_count, 8);

    let e5 = client.get_authority_history_at(&5).unwrap();
    assert_eq!(e5.action, AUTH_HIST_ISSUER_REVOKED);
    assert_eq!(e5.subject, issuer);
    assert_eq!(e5.proposal_ref, p2);
    assert_eq!(e5.approver_count, 6);

    // Reading an 8-approver entry touches the exact same fixed-size record as a
    // 1-approver entry (no iteration over `CouncilProposal.approvals`).
    assert!(
        council_read_cpu <= single_admin_cpu.saturating_mul(2),
        "council history read CPU ({council_read_cpu}) must stay O(1) vs baseline ({single_admin_cpu})"
    );
}

#[test]
fn bounded_ring_evicts_oldest_entries_while_preserving_monotonic_references() {
    let (env, client, admin) = setup();
    client.init(&admin); // seq = 1

    let guardian = Address::generate(&env);
    // Record 265 more transitions (total = 266, 10 past the 256-entry cap).
    for step in 0..265u32 {
        env.ledger()
            .set_timestamp(1_700_000_000 + u64::from(step) + 1);
        if step % 2 == 0 {
            client.set_guardian(&admin, &guardian);
        } else {
            client.clear_guardian(&admin);
        }
    }

    assert_eq!(
        client.get_authority_history_count(),
        MAX_AUTHORITY_HISTORY_ENTRIES
    );
    // Sequences 1..=10 were evicted; sequence 11 is now the oldest retained entry.
    assert_eq!(client.get_authority_history_at(&1), None);
    assert_eq!(client.get_authority_history_at(&10), None);
    assert!(client.get_authority_history_at(&11).is_some());
    assert!(client.get_authority_history_at(&266).is_some());

    // Passing a stale cursor (`1`) fast-forwards cleanly to `earliest_seq` (`11`).
    let page = client.list_authority_history(&1, &5);
    assert_eq!(page.earliest_seq, 11);
    assert_eq!(page.latest_seq, 266);
    assert_eq!(page.entries.len(), 5);
    assert_eq!(page.entries.get(0).unwrap().seq, 11);
    assert_eq!(page.next_cursor, Some(16));
}
