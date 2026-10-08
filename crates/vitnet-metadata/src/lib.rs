//! Streaming `NativeAOT` metadata log decoding and analysis.

mod analysis;
mod decoder;
mod offset;
mod ownership;

pub use analysis::{
    Aggregate, Analysis, AnalysisOptions, Comparison, ComparisonEntry, Concentration, LimitStatus,
    MetadataRecord, Preview, StreamingAnalyzer, StringEntry, analyze, analyze_stream,
    analyze_stream_with_aggregate_limit, compare, metadata_records_from_raw, preview_bytes, top_n,
};
pub use decoder::{
    HEADER, MetadataError, RawRecord, StreamingDecoder, decode_metadata_prefix, encode_header,
    encode_record,
};
pub use offset::{
    CURRENT_OFFSET_BITS, HANDLE_OFFSET_MASK, HANDLE_OFFSET_MODULUS, LEGACY_OFFSET_BITS,
    LowerBoundSizes, NormalizedOffset, OffsetNormalizer, detect_offset_bits, handle_offset,
    handle_offset_with_bits, lower_bound_sizes,
};
pub use ownership::{OwnerCandidate, OwnerSelection, select_owner};
