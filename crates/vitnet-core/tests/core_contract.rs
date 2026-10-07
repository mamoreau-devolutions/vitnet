use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, Instant};
use vitnet_core::{ByteSize, Diagnostic, ExitCode, OptionError, ResourceBudget, ResourceError};

#[test]
fn exit_codes_match_the_documented_process_contract() {
    assert_eq!(ExitCode::Success.as_i32(), 0);
    assert_eq!(ExitCode::ThresholdFailure.as_i32(), 1);
    assert_eq!(ExitCode::InvalidOptions.as_i32(), 2);
    assert_eq!(ExitCode::MalformedInput.as_i32(), 3);
    assert_eq!(ExitCode::IoOrCache.as_i32(), 4);
    assert_eq!(ExitCode::ResourceLimit.as_i32(), 5);
    assert_eq!(ExitCode::InternalInvariant.as_i32(), 6);
}

#[test]
fn byte_size_parses_bytes_and_binary_units_case_insensitively() {
    assert_eq!(ByteSize::from_str("17").unwrap(), ByteSize(17));
    assert_eq!(ByteSize::from_str("17B").unwrap(), ByteSize(17));
    assert_eq!(ByteSize::from_str("2KiB").unwrap(), ByteSize(2 * 1024));
    assert_eq!(
        ByteSize::from_str("3mib").unwrap(),
        ByteSize(3 * 1024 * 1024)
    );
    assert_eq!(
        ByteSize::from_str("4GiB").unwrap(),
        ByteSize(4 * 1024 * 1024 * 1024)
    );
}

#[test]
fn byte_size_rejects_missing_values_unknown_units_and_overflow() {
    assert_eq!(
        ByteSize::from_str("MiB"),
        Err(OptionError::InvalidByteSize("MiB".into()))
    );
    assert_eq!(
        ByteSize::from_str("1MB"),
        Err(OptionError::InvalidByteSize("1MB".into()))
    );
    assert!(matches!(
        ByteSize::from_str("18446744073709551615GiB"),
        Err(OptionError::ByteSizeOverflow(_))
    ));
}

#[test]
fn typed_diagnostic_preserves_all_location_and_recovery_context() {
    let mut diagnostic =
        Diagnostic::malformed("metadata.csv.quote", "unterminated quote").at(91, 7, 9);
    diagnostic.input_path = Some(PathBuf::from("sample.csv"));
    diagnostic.zip_entry = Some("metadata.csv".into());
    diagnostic.expected = Some("closing quote".into());
    diagnostic.actual = Some("end of input".into());
    diagnostic.guidance = Some("regenerate the producer log".into());

    let json = serde_json::to_value(&diagnostic).unwrap();
    assert_eq!(json["code"], "metadata.csv.quote");
    assert_eq!(json["input_path"], "sample.csv");
    assert_eq!(json["zip_entry"], "metadata.csv");
    assert_eq!(json["byte_offset"], 91);
    assert_eq!(json["logical_record"], 7);
    assert_eq!(json["physical_line"], 9);
    assert_eq!(json["expected"], "closing quote");
    assert_eq!(json["actual"], "end of input");
    assert_eq!(json["guidance"], "regenerate the producer log");
    assert_eq!(
        diagnostic.to_string(),
        "metadata.csv.quote: unterminated quote at byte 91, record 7, line 9"
    );
}

#[test]
fn resource_budget_enforces_limits_and_shared_cancellation() {
    let budget = ResourceBudget::new(100, 200, 0, None);
    assert_eq!(budget.worker_limit, 1);
    assert_eq!(budget.check(100, 200), Ok(()));
    assert_eq!(
        budget.check(101, 0),
        Err(ResourceError::Memory {
            limit: 100,
            actual: 101,
        })
    );
    assert_eq!(
        budget.check(0, 201),
        Err(ResourceError::TemporaryDisk {
            limit: 200,
            actual: 201,
        })
    );
    let observer = budget.clone();
    budget.cancel();
    assert_eq!(observer.check(0, 0), Err(ResourceError::Cancelled));

    let expired_deadline = Instant::now()
        .checked_sub(Duration::from_millis(1))
        .expect("one millisecond is representable before the current instant");
    let expired = ResourceBudget::new(100, 200, 1, Some(expired_deadline));
    assert_eq!(expired.check(0, 0), Err(ResourceError::Deadline));
}
