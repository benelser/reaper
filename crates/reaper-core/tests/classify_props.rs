//! The fail-closed proptest battery (SPEC §10/§11): the classifier's safety
//! argument, executable. Criterion 1 lives or dies here.

use camino::Utf8PathBuf;
use proptest::prelude::*;
use reaper_core::{
    admit, classify, plan, Candidate, DetectorId, Disposition, EcosystemId, Facts, GitFacts,
    HeadState, LockState, Policy, ReapStep, RefusalReason, SafetyClass,
};

fn candidate(class: SafetyClass) -> Candidate {
    Candidate {
        path: Utf8PathBuf::from("/w/proj/target"),
        ecosystem: EcosystemId("rust".into()),
        detector: DetectorId("rust-target".into()),
        safety_class: class,
    }
}

/// Fully-established, fully-clean facts: the ONLY shape that may be Reapable.
fn clean_facts(class: SafetyClass) -> Facts {
    let git = matches!(class, SafetyClass::GitWorktree).then(|| GitFacts {
        dirty_entries: Some(0),
        unpushed_commits: Some(0),
        lock: Some(LockState::Unlocked),
        head: Some(HeadState::Attached {
            branch: "main".into(),
        }),
    });
    Facts {
        candidate: candidate(class),
        size_bytes: Some(15_000_000_000),
        idle_days: Some(400),
        live_pids: Some(vec![]),
        active_build: Some(false),
        same_device: Some(true),
        cloud_backed: Some(false),
        git,
    }
}

fn any_class() -> impl Strategy<Value = SafetyClass> {
    prop_oneof![
        Just(SafetyClass::Regenerable {
            regenerate_hint: Some("cargo build".into())
        }),
        Just(SafetyClass::GitWorktree),
        Just(SafetyClass::PackageCache),
    ]
}

fn permissive_policy() -> Policy {
    // Floors at zero and caches included: isolates the FAIL-CLOSED behavior
    // from the policy gates so the None-tests test unknowns, not thresholds.
    Policy::new(
        reaper_core::IdlePolicy {
            worktree_days: 0,
            regenerable_days: 0,
            cache_days: 0,
        },
        0,
        true,
        &[],
    )
    .unwrap()
}

proptest! {
    /// The headline invariant: knock out ANY single load-bearing fact and
    /// Reapable is unreachable — with an Unknown naming what was missing.
    #[test]
    fn any_missing_fact_refuses_unknown(class in any_class(), knockout in 0usize..10) {
        let mut facts = clean_facts(class);
        let is_worktree = matches!(facts.candidate.safety_class, SafetyClass::GitWorktree);
        // Fields 6..10 exist only on worktrees; map them onto 0..6 elsewhere.
        let k = if is_worktree { knockout } else { knockout % 6 };
        match k {
            0 => facts.size_bytes = None,
            1 => facts.idle_days = None,
            2 => facts.live_pids = None,
            3 => facts.active_build = None,
            4 => facts.same_device = None,
            5 => facts.cloud_backed = None,
            6 => facts.git = None,
            7 => facts.git.as_mut().unwrap().dirty_entries = None,
            8 => facts.git.as_mut().unwrap().unpushed_commits = None,
            _ => facts.git.as_mut().unwrap().lock = None,
        }
        match classify(&facts, &permissive_policy()) {
            Disposition::Reapable => prop_assert!(false, "missing fact {} classified Reapable", k),
            Disposition::Refused { reasons } => prop_assert!(
                reasons.iter().any(|r| matches!(r, RefusalReason::Unknown { .. })),
                "refusal lacks Unknown: {:?}", reasons
            ),
        }
    }

    /// Every violated gate produces ITS OWN typed reason, and violations
    /// accumulate — nothing is masked by an earlier gate.
    #[test]
    fn violations_accumulate_with_typed_reasons(
        dirty in 1usize..100,
        unpushed in 1u64..50,
        pids in proptest::collection::vec(1u32..99999, 1..4),
    ) {
        let mut facts = clean_facts(SafetyClass::GitWorktree);
        facts.live_pids = Some(pids.clone());
        let git = facts.git.as_mut().unwrap();
        git.dirty_entries = Some(dirty);
        git.unpushed_commits = Some(unpushed);
        git.lock = Some(LockState::Locked { note: Some("keep".into()) });
        git.head = Some(HeadState::Detached { unreachable_commits: 2 });

        let Disposition::Refused { reasons } = classify(&facts, &permissive_policy()) else {
            return Err(TestCaseError::fail("violations classified Reapable"));
        };
        let dirty_reason = RefusalReason::Dirty { entries: dirty };
        let unpushed_reason = RefusalReason::UnpushedCommits { count: unpushed };
        let live_reason = RefusalReason::LiveProcess { pids };
        prop_assert!(reasons.contains(&dirty_reason), "missing Dirty");
        prop_assert!(reasons.contains(&unpushed_reason), "missing UnpushedCommits");
        prop_assert!(reasons.contains(&live_reason), "missing LiveProcess");
        let locked = reasons.iter().any(|r| matches!(r, RefusalReason::Locked { .. }));
        let detached = reasons.iter().any(|r| matches!(r, RefusalReason::Detached { .. }));
        prop_assert!(locked, "missing Locked");
        prop_assert!(detached, "missing Detached");
    }

    /// Policy floors gate exactly at their boundary, per safety class.
    #[test]
    fn idle_floor_gates_per_class(class in any_class(), idle in 0u64..60) {
        let mut facts = clean_facts(class);
        facts.idle_days = Some(idle);
        let policy = Policy::new(Default::default(), 0, true, &[]).unwrap();
        let floor = policy.min_idle.floor_days(&facts.candidate.safety_class);
        let verdict = classify(&facts, &policy);
        if idle >= floor {
            prop_assert_eq!(verdict, Disposition::Reapable);
        } else {
            let Disposition::Refused { reasons } = verdict else {
                return Err(TestCaseError::fail("young candidate classified Reapable"));
            };
            let too_recent = RefusalReason::TooRecent {
                idle_days: idle,
                min_idle_days: floor,
            };
            prop_assert!(reasons.contains(&too_recent), "missing TooRecent");
        }
    }
}

#[test]
fn clean_facts_are_reapable_for_every_class() {
    for class in [
        SafetyClass::Regenerable {
            regenerate_hint: None,
        },
        SafetyClass::GitWorktree,
        SafetyClass::PackageCache,
    ] {
        let verdict = classify(&clean_facts(class.clone()), &permissive_policy());
        assert_eq!(
            verdict,
            Disposition::Reapable,
            "clean {class:?} not reapable"
        );
    }
}

#[test]
fn protect_list_wins_even_when_fully_reapable() {
    let policy = Policy::new(Default::default(), 0, true, &["/w/proj/**".to_string()]).unwrap();
    let Disposition::Refused { reasons } = classify(
        &clean_facts(SafetyClass::Regenerable {
            regenerate_hint: None,
        }),
        &policy,
    ) else {
        panic!("protected candidate classified Reapable");
    };
    assert!(reasons
        .iter()
        .any(|r| matches!(r, RefusalReason::Protected { .. })));
}

#[test]
fn caches_refuse_unless_opted_in() {
    let default_policy = Policy::default(); // include_caches = false
    let mut facts = clean_facts(SafetyClass::PackageCache);
    facts.idle_days = Some(400); // clear the 30d floor: isolate the opt-in gate
    let Disposition::Refused { reasons } = classify(&facts, &default_policy) else {
        panic!("cache reapable without --include-caches");
    };
    assert!(reasons.contains(&RefusalReason::CachesExcluded));
}

#[test]
fn plan_is_typed_ordered_and_only_reachable_through_admission() {
    let policy = permissive_policy();
    let wt = admit(&clean_facts(SafetyClass::GitWorktree), &policy).unwrap();
    let mut regen_facts = clean_facts(SafetyClass::Regenerable {
        regenerate_hint: Some("cargo build".into()),
    });
    regen_facts.candidate.path = Utf8PathBuf::from("/a/first/target");
    let regen = admit(&regen_facts, &policy).unwrap();

    // Input order is worktree-first; the plan must be path-ordered anyway.
    let p = plan(&[wt, regen]);
    assert_eq!(p.steps.len(), 2);
    assert!(matches!(
        &p.steps[0],
        ReapStep::DeleteDir { path, regenerate_hint: Some(h) }
            if path == "/a/first/target" && h == "cargo build"
    ));
    assert!(matches!(
        &p.steps[1],
        ReapStep::RemoveWorktree { branch: Some(b), .. } if b == "main"
    ));

    // And the refused can never get in: admit() is the only door.
    let dirty = Facts {
        git: Some(GitFacts {
            dirty_entries: Some(3),
            unpushed_commits: Some(0),
            lock: Some(LockState::Unlocked),
            head: Some(HeadState::Attached {
                branch: "main".into(),
            }),
        }),
        ..clean_facts(SafetyClass::GitWorktree)
    };
    assert!(admit(&dirty, &policy).is_err());
}
