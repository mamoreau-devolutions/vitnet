use crate::{AttributionError, error};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GenericShape {
    pub family: String,
    pub arguments: Vec<String>,
    pub group_boundaries: Vec<usize>,
    pub canonical_shared: bool,
    pub producer_name: String,
}

/// Parses nested producer shapes without claiming to demangle managed identities.
///
/// # Errors
///
/// Rejects unbalanced, excessive-depth or excessive-length shapes.
pub fn parse_shape(name: &str) -> Result<Option<GenericShape>, AttributionError> {
    if name.len() > 1024 * 1024 {
        return Err(error(
            "resource.memory_limit",
            "generic shape exceeds 1 MiB",
        ));
    }
    let Some(open) = name.find('<') else {
        return Ok(None);
    };
    let mut arguments = Vec::new();
    let mut group_boundaries = Vec::new();
    let mut family = name[..open].to_owned();
    let mut group_open = open;
    loop {
        let close = closing_bracket(name, group_open)?;
        arguments.extend(parse_arguments(&name[group_open + 1..close])?);
        group_boundaries.push(arguments.len());
        let suffix = &name[close + 1..];
        if let Some(next) = suffix.find('<') {
            if suffix[..next].contains('>') {
                return Err(error(
                    "attribution.generic.syntax",
                    "unmatched generic close",
                ));
            }
            family.push_str("<>");
            family.push_str(&suffix[..next]);
            group_open = close + 1 + next;
        } else {
            if suffix.contains('>') {
                return Err(error(
                    "attribution.generic.syntax",
                    "unmatched generic close",
                ));
            }
            family.push_str("<>");
            if !suffix.is_empty() {
                family.push_str(suffix);
            }
            break;
        }
    }
    Ok(Some(GenericShape {
        family,
        arguments,
        group_boundaries,
        canonical_shared: name.contains("___Canon") || name.contains("__Canon"),
        producer_name: name.into(),
    }))
}

fn closing_bracket(name: &str, open: usize) -> Result<usize, AttributionError> {
    let mut depth = 0_usize;
    for (offset, byte) in name.as_bytes().iter().enumerate().skip(open) {
        if *byte == b'<' {
            depth += 1;
            if depth > 64 {
                return Err(error(
                    "attribution.generic.depth",
                    "generic nesting exceeds 64",
                ));
            }
        } else if *byte == b'>' {
            depth -= 1;
            if depth == 0 {
                return Ok(offset);
            }
        }
    }
    Err(error(
        "attribution.generic.syntax",
        "unclosed generic arguments",
    ))
}

fn parse_arguments(inner: &str) -> Result<Vec<String>, AttributionError> {
    let mut arguments = Vec::new();
    let mut start = 0;
    let mut cursor = 0;
    let mut nesting = 0_usize;
    let inner_bytes = inner.as_bytes();
    while cursor < inner_bytes.len() {
        match inner_bytes[cursor] {
            b'<' => nesting += 1,
            b'>' => nesting -= 1,
            _ => {}
        }
        let underscore_separator = cursor > start
            && cursor + 1 < inner_bytes.len()
            && &inner_bytes[cursor..cursor + 2] == b"__"
            && inner_bytes[cursor - 1] != b'_'
            && inner_bytes.get(cursor + 2) != Some(&b'_');
        let separator = nesting == 0 && (inner_bytes[cursor] == b',' || underscore_separator);
        if separator {
            let argument = inner[start..cursor].trim();
            if argument.is_empty() {
                return Err(error(
                    "attribution.generic.syntax",
                    "empty generic argument",
                ));
            }
            arguments.push(argument.to_owned());
            cursor += if underscore_separator { 2 } else { 1 };
            start = cursor;
        } else {
            cursor += 1;
        }
    }
    let final_argument = inner[start..].trim();
    if final_argument.is_empty() {
        return Err(error(
            "attribution.generic.syntax",
            "empty final generic argument",
        ));
    }
    arguments.push(final_argument.into());
    Ok(arguments)
}
