use crate::MetadataError;
use vitnet_core::Diagnostic;

pub const CURRENT_OFFSET_BITS: u8 = 25;
pub const LEGACY_OFFSET_BITS: u8 = 24;
pub const HANDLE_OFFSET_MASK: u32 = (1 << CURRENT_OFFSET_BITS) - 1;
pub const HANDLE_OFFSET_MODULUS: u64 = 1 << CURRENT_OFFSET_BITS;

#[must_use]
pub const fn handle_offset(handle: u32) -> u32 {
    handle & HANDLE_OFFSET_MASK
}

#[must_use]
pub const fn handle_offset_with_bits(handle: u32, offset_bits: u8) -> u32 {
    handle & ((1_u32 << offset_bits) - 1)
}

/// Detects the producer handle layout from the packed kind and textual kind.
///
/// Unknown future kinds conservatively use the current 25-bit layout.
#[must_use]
pub fn detect_offset_bits(handle: u32, kind: &[u8]) -> u8 {
    let Some((current_kind, legacy_kind)) = handle_type_values(kind) else {
        return CURRENT_OFFSET_BITS;
    };
    let current_matches = (handle >> CURRENT_OFFSET_BITS) as u8 == current_kind;
    let legacy_matches =
        legacy_kind.is_some_and(|value| (handle >> LEGACY_OFFSET_BITS) as u8 == value);
    match (current_matches, legacy_matches) {
        (false, true) => LEGACY_OFFSET_BITS,
        _ => CURRENT_OFFSET_BITS,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalizedOffset {
    pub physical: u32,
    pub logical: u64,
    pub wrapped: bool,
}

#[derive(Clone, Debug)]
pub struct OffsetNormalizer {
    previous_physical: Option<u32>,
    epoch: u64,
    offset_bits: u8,
    mask: u32,
    modulus: u64,
    strict: bool,
}

impl OffsetNormalizer {
    #[must_use]
    pub const fn new(strict: bool) -> Self {
        Self::with_bits(strict, CURRENT_OFFSET_BITS)
    }

    #[must_use]
    pub const fn with_bits(strict: bool, offset_bits: u8) -> Self {
        Self {
            previous_physical: None,
            epoch: 0,
            offset_bits,
            mask: (1_u32 << offset_bits) - 1,
            modulus: 1_u64 << offset_bits,
            strict,
        }
    }

    #[must_use]
    pub const fn offset_bits(&self) -> u8 {
        self.offset_bits
    }

    #[must_use]
    pub const fn limit(&self) -> u64 {
        self.mask as u64
    }

    #[must_use]
    pub const fn is_strict(&self) -> bool {
        self.strict
    }

    /// Adds a producer handle and reconstructs its logical offset.
    ///
    /// # Errors
    ///
    /// Returns a typed diagnostic for a strict impossible sequence or a `u64`
    /// epoch overflow.
    pub fn push(&mut self, handle: u32) -> Result<NormalizedOffset, MetadataError> {
        let physical = handle & self.mask;
        let mut wrapped = false;
        if let Some(previous) = self.previous_physical
            && physical < previous
        {
            let backward = u64::from(previous - physical);
            if self.strict && backward <= self.modulus / 2 {
                let mut diagnostic = Diagnostic::malformed(
                    "metadata.offset.sequence",
                    format!(
                        "backwards offset cannot be explained by a {}-bit rollover",
                        self.offset_bits
                    ),
                );
                diagnostic.expected = Some(format!(
                    "offset >= {previous} or rollover drop > {}",
                    self.modulus / 2
                ));
                diagnostic.actual = Some(physical.to_string());
                diagnostic.guidance = Some(
                    "rerun without --strict only when partial producer logs are expected".into(),
                );
                return Err(MetadataError {
                    diagnostic: Box::new(diagnostic),
                });
            }
            self.epoch = self
                .epoch
                .checked_add(self.modulus)
                .ok_or_else(|| MetadataError {
                    diagnostic: Box::new(Diagnostic::malformed(
                        "metadata.offset.overflow",
                        "logical offset epoch overflowed u64",
                    )),
                })?;
            wrapped = true;
        }

        self.previous_physical = Some(physical);
        Ok(NormalizedOffset {
            physical,
            logical: self.epoch + u64::from(physical),
            wrapped,
        })
    }
}

fn handle_type_values(kind: &[u8]) -> Option<(u8, Option<u8>)> {
    const CURRENT: &[&[u8]] = &[
        b"ArraySignature",
        b"ByReferenceSignature",
        b"ConstantBooleanArray",
        b"ConstantBooleanValue",
        b"ConstantByteArray",
        b"ConstantByteValue",
        b"ConstantCharArray",
        b"ConstantCharValue",
        b"ConstantDoubleArray",
        b"ConstantDoubleValue",
        b"ConstantEnumArray",
        b"ConstantEnumValue",
        b"ConstantHandleArray",
        b"ConstantInt16Array",
        b"ConstantInt16Value",
        b"ConstantInt32Array",
        b"ConstantInt32Value",
        b"ConstantInt64Array",
        b"ConstantInt64Value",
        b"ConstantReferenceValue",
        b"ConstantSByteArray",
        b"ConstantSByteValue",
        b"ConstantSingleArray",
        b"ConstantSingleValue",
        b"ConstantStringArray",
        b"ConstantStringValue",
        b"ConstantUInt16Array",
        b"ConstantUInt16Value",
        b"ConstantUInt32Array",
        b"ConstantUInt32Value",
        b"ConstantUInt64Array",
        b"ConstantUInt64Value",
        b"CustomAttribute",
        b"Event",
        b"Field",
        b"FieldSignature",
        b"FunctionPointerSignature",
        b"GenericParameter",
        b"MemberReference",
        b"Method",
        b"MethodInstantiation",
        b"MethodSemantics",
        b"MethodSignature",
        b"MethodTypeVariableSignature",
        b"ModifiedType",
        b"NamedArgument",
        b"NamespaceDefinition",
        b"NamespaceReference",
        b"Parameter",
        b"PointerSignature",
        b"Property",
        b"PropertySignature",
        b"QualifiedField",
        b"QualifiedMethod",
        b"SZArraySignature",
        b"ScopeDefinition",
        b"ScopeReference",
        b"TypeDefinition",
        b"TypeForwarder",
        b"TypeInstantiationSignature",
        b"TypeReference",
        b"TypeSpecification",
        b"TypeVariableSignature",
    ];
    if kind.eq_ignore_ascii_case(b"ConstantBoxedEnumValue") {
        return Some((0, Some(5)));
    }
    let current = CURRENT
        .iter()
        .position(|name| kind.eq_ignore_ascii_case(name))
        .and_then(|index| u8::try_from(index + 1).ok())?;
    let legacy = match current {
        5..=11 => Some(current + 1),
        12 => None,
        _ => Some(current),
    };
    Some((current, legacy))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LowerBoundSizes {
    pub record_lower_bounds: Vec<u64>,
    pub total_lower_bound: u64,
    pub final_record_exact: bool,
}

#[must_use]
pub fn lower_bound_sizes(offsets: &[u64]) -> LowerBoundSizes {
    let mut sizes = offsets
        .windows(2)
        .map(|window| window[1].saturating_sub(window[0]))
        .collect::<Vec<_>>();
    if !offsets.is_empty() {
        sizes.push(0);
    }
    LowerBoundSizes {
        record_lower_bounds: sizes,
        total_lower_bound: offsets.last().copied().unwrap_or(0),
        final_record_exact: false,
    }
}
