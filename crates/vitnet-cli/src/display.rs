use std::fmt::Write as _;

const UNITS: [&str; 7] = ["B", "KB", "MB", "GB", "TB", "PB", "EB"];

pub(crate) fn bytes(value: u64) -> String {
    magnitude(u128::from(value))
}

fn magnitude(value: u128) -> String {
    let mut unit = 0;
    let mut scale = 1_u128;
    while value / scale >= 1000 && unit + 1 < UNITS.len() {
        unit += 1;
        scale *= 1000;
    }
    let mut hundredths = (value / scale) * 100 + (value % scale * 100 + scale / 2) / scale;
    if hundredths >= 100_000 && unit + 1 < UNITS.len() {
        unit += 1;
        scale *= 1000;
        hundredths = (value / scale) * 100 + (value % scale * 100 + scale / 2) / scale;
    }
    let whole = hundredths / 100;
    let fraction = hundredths % 100;
    let number = if fraction == 0 {
        whole.to_string()
    } else if fraction % 10 == 0 {
        format!("{whole}.{}", fraction / 10)
    } else {
        format!("{whole}.{fraction:02}")
    };
    format!("{number} {}", UNITS[unit])
}

pub(crate) fn exact(value: u64) -> String {
    wide_exact(u128::from(value))
}

pub(crate) fn wide_exact(value: u128) -> String {
    if value < 1000 {
        magnitude(value)
    } else {
        format!("{} ({value} B)", magnitude(value))
    }
}

pub(crate) fn optional(value: Option<u64>) -> String {
    value.map_or_else(|| "Unknown".into(), exact)
}

pub(crate) fn signed(value: i128) -> String {
    format!(
        "{}{} ({value:+} B)",
        match value.cmp(&0) {
            std::cmp::Ordering::Less => "-",
            std::cmp::Ordering::Greater => "+",
            std::cmp::Ordering::Equal => "",
        },
        magnitude(value.unsigned_abs())
    )
}

pub(crate) fn percent(value: u64, total: Option<u64>) -> String {
    let Some(total) = total.filter(|total| *total != 0) else {
        return "Unknown".into();
    };
    let hundredths = (u128::from(value) * 10_000 + u128::from(total) / 2) / u128::from(total);
    basis_points(hundredths)
}

pub(crate) fn basis_points(value: u128) -> String {
    format!("{}.{:02}%", value / 100, value % 100)
}

pub(crate) fn text(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            c if terminal_control(c) => {
                write!(output, "\\u{{{:x}}}", u32::from(c)).unwrap();
            }
            c => output.push(c),
        }
    }
    output
}

pub(crate) fn terminal_control(character: char) -> bool {
    character.is_control() || matches!(character, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}
