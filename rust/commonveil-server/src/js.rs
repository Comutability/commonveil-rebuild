//! The few JavaScript rules the store depends on, so queries and sorting answer exactly as the
//! Node.js server's did: strict equality, relational comparison (`<`, `>=`, ...) and `Number()`.
use std::cmp::Ordering;

use serde_json::Value;

/// `ToNumber`, for the values JSON can hold (`None` is `undefined`).
pub fn to_number(v: Option<&Value>) -> f64 {
    match v {
        None => f64::NAN,
        Some(Value::Null) => 0.0,
        Some(Value::Bool(b)) => f64::from(u8::from(*b)),
        Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
        Some(Value::String(s)) => string_to_number(s),
        // Objects become "[object Object]" (NaN); arrays join their items with commas.
        Some(Value::Array(a)) => match a.len() {
            0 => 0.0,
            1 => match &a[0] {
                Value::Array(_) | Value::Object(_) => f64::NAN,
                Value::Null => 0.0,
                x => to_number(Some(x)),
            },
            _ => f64::NAN,
        },
        Some(Value::Object(_)) => f64::NAN,
    }
}

/// `Number(string)`: whitespace trimmed, empty is 0, decimal, hex/octal/binary and Infinity.
pub fn string_to_number(s: &str) -> f64 {
    let t = s.trim_matches(is_js_space);
    if t.is_empty() {
        return 0.0;
    }
    for (prefix, radix) in [("0x", 16), ("0X", 16), ("0o", 8), ("0O", 8), ("0b", 2), ("0B", 2)] {
        if let Some(digits) = t.strip_prefix(prefix) {
            return if !digits.is_empty() && digits.chars().all(|c| c.is_digit(radix)) { digits.chars().fold(0.0, |n, c| n * f64::from(radix) + f64::from(c.to_digit(radix).unwrap())) } else { f64::NAN };
        }
    }
    match t {
        "Infinity" | "+Infinity" => return f64::INFINITY,
        "-Infinity" => return f64::NEG_INFINITY,
        _ => {}
    }
    let ok = t.chars().all(|c| c.is_ascii_digit() || matches!(c, '.' | 'e' | 'E' | '+' | '-'));
    if ok { t.parse::<f64>().unwrap_or(f64::NAN) } else { f64::NAN }
}

/// `String(value)` for a primitive (what `<` uses when one side isn't a number).
fn to_primitive_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Array(a) => Some(a.iter().map(|x| match x {
            Value::Null => String::new(),
            Value::String(s) => s.clone(),
            other => to_primitive_string(other).unwrap_or_default(),
        }).collect::<Vec<_>>().join(",")),
        Value::Object(_) => Some("[object Object]".into()),
        _ => None,
    }
}

fn utf16_cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// The abstract relational comparison behind `a < b`: `Some(true)`, `Some(false)`, or `None`
/// when JavaScript would answer `undefined` (a NaN on either side), which every operator treats
/// as false.
fn less_than(a: Option<&Value>, b: Option<&Value>) -> Option<bool> {
    let (pa, pb) = (a.and_then(to_primitive_string), b.and_then(to_primitive_string));
    if let (Some(x), Some(y)) = (&pa, &pb) {
        if matches!(a, Some(Value::String(_) | Value::Array(_) | Value::Object(_))) && matches!(b, Some(Value::String(_) | Value::Array(_) | Value::Object(_))) {
            return Some(utf16_cmp(x, y) == Ordering::Less);
        }
    }
    let num = |v: Option<&Value>, p: &Option<String>| match (v, p) {
        (Some(Value::Array(_) | Value::Object(_)), Some(s)) => string_to_number(s),
        _ => to_number(v),
    };
    let (x, y) = (num(a, &pa), num(b, &pb));
    if x.is_nan() || y.is_nan() {
        None
    } else {
        Some(x < y)
    }
}

pub fn lt(a: Option<&Value>, b: Option<&Value>) -> bool {
    less_than(a, b) == Some(true)
}
pub fn gt(a: Option<&Value>, b: Option<&Value>) -> bool {
    less_than(b, a) == Some(true)
}
pub fn le(a: Option<&Value>, b: Option<&Value>) -> bool {
    less_than(b, a) == Some(false)
}
pub fn ge(a: Option<&Value>, b: Option<&Value>) -> bool {
    less_than(a, b) == Some(false)
}

/// `===` between two JSON values. Objects and arrays are only ever equal to themselves in
/// JavaScript, and two separately parsed ones never are.
pub fn strict_eq(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(Value::Null), Some(Value::Null)) => true,
        (Some(Value::Bool(x)), Some(Value::Bool(y))) => x == y,
        (Some(Value::Number(x)), Some(Value::Number(y))) => x.as_f64() == y.as_f64(),
        (Some(Value::String(x)), Some(Value::String(y))) => x == y,
        _ => false,
    }
}

/// The sort comparison the store uses: equal is 0, a missing or null value sorts last, then `<`.
pub fn compare(a: Option<&Value>, b: Option<&Value>) -> Ordering {
    if strict_eq(a, b) {
        return Ordering::Equal;
    }
    let missing = |v: Option<&Value>| matches!(v, None | Some(Value::Null));
    if missing(a) {
        return Ordering::Greater;
    }
    if missing(b) {
        return Ordering::Less;
    }
    if lt(a, b) { Ordering::Less } else { Ordering::Greater }
}

/// `String.prototype.trim`: JavaScript's whitespace and line terminators, both ends.
pub fn trim(s: &str) -> String {
    s.trim_matches(is_js_space).to_string()
}

/// JavaScript's WhiteSpace and LineTerminator (not Rust's `is_whitespace`, which also counts
/// U+0085).
pub fn is_js_space(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\u{B}' | '\u{C}' | '\r' | ' ' | '\u{A0}' | '\u{1680}' | '\u{2000}'..='\u{200A}' | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}' | '\u{3000}' | '\u{FEFF}')
}

/// `String(value)` (`None` is `undefined`).
pub fn to_js_string(v: Option<&Value>) -> String {
    match v {
        None => "undefined".into(),
        Some(Value::Null) => "null".into(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => match n.as_f64() {
            Some(f) if f.fract() == 0.0 && f.abs() < 1e21 => format!("{}", f as i64),
            Some(f) => format!("{f}"),
            None => n.to_string(),
        },
        Some(other) => to_primitive_string(other).unwrap_or_default(),
    }
}

/// A JSON value is "truthy" as JavaScript sees it.
pub fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn comparisons_follow_javascript() {
        let j = |v: Value| v;
        assert!(lt(Some(&j(json!(2))), Some(&j(json!(10)))));
        assert!(lt(Some(&j(json!("10"))), Some(&j(json!("2")))), "strings compare as strings");
        assert!(lt(Some(&j(json!("2"))), Some(&j(json!(10)))), "a string against a number is a number");
        assert!(!lt(None, Some(&j(json!(1)))) && !ge(None, Some(&j(json!(1)))), "undefined compares as NaN");
        assert!(ge(Some(&j(json!(null))), Some(&j(json!(0)))), "null is 0");
        assert!(!ge(Some(&j(json!("abc"))), Some(&j(json!(1)))));
        assert!(strict_eq(Some(&j(json!(1))), Some(&j(json!(1.0)))));
        assert!(!strict_eq(Some(&j(json!(1))), Some(&j(json!("1")))));
        assert!(!strict_eq(Some(&j(json!([1]))), Some(&j(json!([1])))));
        assert_eq!(compare(None, Some(&j(json!("a")))), Ordering::Greater);
        assert_eq!(compare(Some(&j(json!("a"))), Some(&j(json!(null)))), Ordering::Less);
        assert_eq!(string_to_number(" 0x1f "), 31.0);
        assert!(string_to_number("1_000").is_nan());
    }
}
