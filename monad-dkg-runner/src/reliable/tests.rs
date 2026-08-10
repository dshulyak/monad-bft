use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scope {
    Item(u8),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Evidence {
    Item(u8),
    Phase,
}

struct TestPolicy;

impl ObsolescencePolicy for TestPolicy {
    type Scope = Scope;
    type Evidence = Evidence;

    fn obsolete(scope: &Self::Scope, evidence: &Self::Evidence) -> bool {
        matches!(evidence, Evidence::Phase)
            || matches!((scope, evidence), (Scope::Item(left), Evidence::Item(right)) if left == right)
    }
}

fn config() -> RetryConfig {
    RetryConfig::new(
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(30),
        Duration::ZERO,
    )
}

fn outbox() -> RetryScheduler<u8, u8, &'static str, TestPolicy> {
    RetryScheduler::new(config())
}

#[test]
fn one_message_is_shared_by_all_new_recipients() {
    let now = Instant::now();
    let mut outbox = outbox();
    let sends = outbox
        .enqueue(1, [2, 3, 4], "message", Some(Scope::Item(1)), now)
        .unwrap();
    assert_eq!(
        sends.iter().map(|send| send.to).collect::<Vec<_>>(),
        [2, 3, 4]
    );

    assert!(outbox
        .enqueue(1, [2], "message", Some(Scope::Item(1)), now)
        .unwrap()
        .is_empty());
    assert_eq!(outbox.messages.len(), 1);
    assert_eq!(outbox.messages[&1].recipients.len(), 3);
}

#[test]
fn conflicting_message_id_is_an_error() {
    let now = Instant::now();
    let mut outbox = outbox();
    outbox
        .enqueue(1, [2], "first", Some(Scope::Item(1)), now)
        .unwrap();
    assert!(matches!(
        outbox.enqueue(1, [3], "second", Some(Scope::Item(1)), now),
        Err(EnqueueError)
    ));
    assert!(matches!(
        outbox.enqueue(1, [3], "first", Some(Scope::Item(2)), now),
        Err(EnqueueError)
    ));
}

#[test]
fn retries_use_linear_backoff_capped_at_maximum() {
    let now = Instant::now();
    let mut outbox = outbox();
    outbox.enqueue(1, [2], "message", None, now).unwrap();

    let first = outbox.next_timer().unwrap();
    assert_eq!(first.duration_since(now), Duration::from_secs(2));
    assert_eq!(outbox.retry_due(first).len(), 1);
    let second = outbox.next_timer().unwrap();
    assert_eq!(second.duration_since(first), Duration::from_secs(4));

    for _ in 0..80 {
        let due = outbox.next_timer().unwrap();
        outbox.retry_due(due);
    }
    assert_eq!(
        outbox.messages[&1].recipients[&2].retry_delay,
        Duration::from_secs(30)
    );
}

#[test]
fn retries_follow_deadline_order() {
    let now = Instant::now();
    let mut outbox = outbox();
    outbox.enqueue(1, [2], "first", None, now).unwrap();
    outbox
        .enqueue(2, [3], "second", None, now + Duration::from_secs(1))
        .unwrap();

    let first_deadline = outbox.next_timer().unwrap();
    let sends = outbox.retry_due(first_deadline);
    assert_eq!(sends.len(), 1);
    assert_eq!(sends[0].payload, "first");

    let second_deadline = outbox.next_timer().unwrap();
    assert_eq!(second_deadline, now + Duration::from_secs(3));
    let sends = outbox.retry_due(second_deadline);
    assert_eq!(sends.len(), 1);
    assert_eq!(sends[0].payload, "second");
}

#[test]
fn evidence_removes_matching_messages_and_rejects_late_replay() {
    let now = Instant::now();
    let mut outbox = outbox();
    outbox
        .enqueue(1, [1], "one", Some(Scope::Item(1)), now)
        .unwrap();
    outbox
        .enqueue(2, [2], "two", Some(Scope::Item(2)), now)
        .unwrap();
    outbox.enqueue(3, [3], "session", None, now).unwrap();

    outbox.observe(Evidence::Item(1));
    assert!(!outbox.messages.contains_key(&1));
    assert!(outbox.messages.contains_key(&2));
    assert!(outbox.messages.contains_key(&3));
    assert_eq!(outbox.deadlines.len(), 2);
    assert!(outbox
        .enqueue(4, [4], "late", Some(Scope::Item(1)), now)
        .unwrap()
        .is_empty());

    outbox.observe(Evidence::Phase);
    assert!(!outbox.messages.contains_key(&2));
    assert!(outbox.messages.contains_key(&3));
    assert_eq!(outbox.deadlines.len(), 1);
}

#[test]
fn completed_message_has_no_more_retries() {
    let now = Instant::now();
    let mut outbox = outbox();
    outbox
        .enqueue(1, [2, 3], "request", Some(Scope::Item(1)), now)
        .unwrap();

    outbox.complete(&1);

    assert!(!outbox.messages.contains_key(&1));
    assert!(outbox.deadlines.is_empty());
    assert!(outbox.next_timer().is_none());
}

#[test]
fn acknowledgement_completes_only_the_confirming_recipient() {
    let now = Instant::now();
    let mut outbox = outbox();
    outbox
        .enqueue(1, [2, 3], "message", Some(Scope::Item(1)), now)
        .unwrap();

    outbox.acknowledge(&1, 2);

    assert_eq!(outbox.pending_count(), 1);
    assert!(!outbox.messages[&1].recipients.contains_key(&2));
    assert!(outbox.messages[&1].recipients.contains_key(&3));

    outbox.acknowledge(&1, 3);
    assert!(!outbox.messages.contains_key(&1));
    assert!(outbox.next_timer().is_none());
}
