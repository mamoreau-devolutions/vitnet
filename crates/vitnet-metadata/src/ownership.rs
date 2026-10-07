#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerCandidate {
    pub owner_index: usize,
    pub source_index: usize,
    pub depth: u32,
    pub child_handle: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerSelection {
    pub owner_index: usize,
    pub distance: usize,
    pub depth: u32,
}

/// Chooses the nearest producer reference. Equal-distance references prefer the
/// deepest owner scope, then the earlier source for stable results.
#[must_use]
pub fn select_owner(
    record_index: usize,
    handle: u32,
    candidates: &[OwnerCandidate],
) -> Option<OwnerSelection> {
    candidates
        .iter()
        .filter(|candidate| candidate.child_handle == handle)
        .map(|candidate| OwnerSelection {
            owner_index: candidate.owner_index,
            distance: candidate.source_index.abs_diff(record_index),
            depth: candidate.depth,
        })
        .min_by(|left, right| {
            left.distance
                .cmp(&right.distance)
                .then_with(|| right.depth.cmp(&left.depth))
                .then_with(|| left.owner_index.cmp(&right.owner_index))
        })
}
