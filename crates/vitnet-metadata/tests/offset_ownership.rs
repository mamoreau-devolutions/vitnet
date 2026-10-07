use proptest::prelude::*;
use vitnet_metadata::{
    HANDLE_OFFSET_MASK, HANDLE_OFFSET_MODULUS, LEGACY_OFFSET_BITS, OffsetNormalizer,
    OwnerCandidate, detect_offset_bits, handle_offset, lower_bound_sizes, select_owner,
};

#[test]
fn handle_offset_uses_only_the_low_25_bits() {
    let low = 0x01ab_cdef & HANDLE_OFFSET_MASK;
    assert_eq!(handle_offset(low), low);
    assert_eq!(handle_offset(0xfe00_0000 | low), low);
}

#[test]
fn offset_normalizer_unwraps_the_exact_25_bit_rollover() {
    let mut normalizer = OffsetNormalizer::new(true);
    let before = normalizer.push(HANDLE_OFFSET_MASK - 1).unwrap();
    let after = normalizer.push(2).unwrap();
    assert_eq!(before.logical, HANDLE_OFFSET_MODULUS - 2);
    assert_eq!(after.logical, HANDLE_OFFSET_MODULUS + 2);
    assert!(!before.wrapped);
    assert!(after.wrapped);
}

#[test]
fn producer_layout_detection_distinguishes_legacy_and_current_handles() {
    assert_eq!(
        detect_offset_bits(0x3800_1234, b"ScopeDefinition"),
        LEGACY_OFFSET_BITS
    );
    assert_eq!(detect_offset_bits(0x7000_1234, b"ScopeDefinition"), 25);

    let mut legacy = OffsetNormalizer::with_bits(true, LEGACY_OFFSET_BITS);
    let before = legacy.push(0x38ff_fffe).unwrap();
    let after = legacy.push(0x3800_0002).unwrap();
    assert_eq!(before.logical, (1 << 24) - 2);
    assert_eq!(after.logical, (1 << 24) + 2);
    assert_eq!(legacy.limit(), (1 << 24) - 1);
}

#[test]
fn strict_offset_normalizer_rejects_an_impossible_small_backwards_step() {
    let mut normalizer = OffsetNormalizer::new(true);
    normalizer.push(1_000).unwrap();
    let error = normalizer.push(999).unwrap_err();
    assert_eq!(error.diagnostic.code, "metadata.offset.sequence");
    assert_eq!(error.diagnostic.actual.as_deref(), Some("999"));
    assert!(error.diagnostic.guidance.is_some());
}

#[test]
fn strict_rollover_boundary_rejects_half_modulus_and_accepts_one_more() {
    let previous = HANDLE_OFFSET_MASK;
    let half_drop_current = previous - u32::try_from(HANDLE_OFFSET_MODULUS / 2).unwrap();
    let mut rejected = OffsetNormalizer::new(true);
    rejected.push(previous).unwrap();
    assert!(rejected.push(half_drop_current).is_err());

    let mut accepted = OffsetNormalizer::new(true);
    accepted.push(previous).unwrap();
    let rollover = accepted.push(half_drop_current - 1).unwrap();
    assert!(rollover.wrapped);
    assert_eq!(
        rollover.logical,
        HANDLE_OFFSET_MODULUS + u64::from(half_drop_current - 1)
    );
}

#[test]
fn lenient_offset_normalizer_recovers_partial_backwards_sequences_as_a_wrap() {
    let mut normalizer = OffsetNormalizer::new(false);
    normalizer.push(1_000).unwrap();
    let recovered = normalizer.push(999).unwrap();
    assert_eq!(recovered.logical, HANDLE_OFFSET_MODULUS + 999);
    assert!(recovered.wrapped);
}

#[test]
fn record_starts_make_totals_and_the_final_record_lower_bounds() {
    let sizes = lower_bound_sizes(&[0, 10, 25]);
    assert_eq!(sizes.record_lower_bounds, vec![10, 15, 0]);
    assert_eq!(sizes.total_lower_bound, 25);
    assert!(!sizes.final_record_exact);

    let empty = lower_bound_sizes(&[]);
    assert_eq!(empty.record_lower_bounds, Vec::<u64>::new());
    assert_eq!(empty.total_lower_bound, 0);
    assert!(!empty.final_record_exact);
}

#[test]
fn duplicate_handle_ownership_selects_the_nearest_reference() {
    let candidates = vec![
        OwnerCandidate {
            owner_index: 1,
            source_index: 1,
            depth: 3,
            child_handle: 42,
        },
        OwnerCandidate {
            owner_index: 8,
            source_index: 8,
            depth: 1,
            child_handle: 42,
        },
    ];
    let selected = select_owner(7, 42, &candidates).unwrap();
    assert_eq!(selected.owner_index, 8);
    assert_eq!(selected.distance, 1);
}

#[test]
fn equal_distance_duplicate_handle_ownership_selects_the_deepest_scope() {
    let candidates = vec![
        OwnerCandidate {
            owner_index: 2,
            source_index: 4,
            depth: 1,
            child_handle: 42,
        },
        OwnerCandidate {
            owner_index: 9,
            source_index: 6,
            depth: 3,
            child_handle: 42,
        },
    ];
    let selected = select_owner(5, 42, &candidates).unwrap();
    assert_eq!(selected.owner_index, 9);
    assert_eq!(selected.depth, 3);
}

#[test]
fn equal_distance_and_depth_ownership_uses_stable_earlier_owner_index() {
    let candidates = vec![
        OwnerCandidate {
            owner_index: 9,
            source_index: 4,
            depth: 3,
            child_handle: 42,
        },
        OwnerCandidate {
            owner_index: 2,
            source_index: 6,
            depth: 3,
            child_handle: 42,
        },
    ];
    let selected = select_owner(5, 42, &candidates).unwrap();
    assert_eq!(selected.owner_index, 2);
    assert_eq!(selected.distance, 1);
    assert_eq!(selected.depth, 3);
}

proptest! {
    #[test]
    fn normalized_offsets_are_monotonic_across_valid_rollovers(
        epochs in prop::collection::vec((0_u32..1_000_000, 0_u32..1_000_000), 1..30)
    ) {
        let mut handles = Vec::new();
        for (low, high_tail) in epochs {
            let high = HANDLE_OFFSET_MASK - high_tail;
            handles.push(high);
            handles.push(low);
        }
        let mut normalizer = OffsetNormalizer::new(true);
        let logical = handles.into_iter()
            .map(|handle| normalizer.push(handle).unwrap().logical)
            .collect::<Vec<_>>();
        prop_assert!(logical.windows(2).all(|window| window[0] <= window[1]));
    }
}
