//! `Date.parse` for the forms the backend writes and reads (ISO 8601, as `toISOString()` writes it,
//! with or without the zone). A time with no zone is read as UTC, which is what JavaScript does on
//! a server whose clock is UTC (the Docker image's).
pub fn parse(s: &str) -> Option<f64> {
    let re = regex::Regex::new(r"^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?(Z|[+-]\d{2}:\d{2})?)?$").unwrap();
    let c = re.captures(s)?;
    let n = |i: usize| c.get(i).map_or(0, |m| m.as_str().parse::<i64>().unwrap_or(0));
    let (y, mo, d, h, mi, se) = (n(1), n(2), n(3), n(4), n(5), n(6));
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 24 || mi > 59 || se > 59 || (h == 24 && (mi, se) != (0, 0)) {
        return None;
    }
    let dim = [31, if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][(mo - 1) as usize];
    if d > dim {
        return None;
    }
    let ms = c.get(7).map_or(0, |m| {
        let f = format!("{:0<3}", &m.as_str()[..m.as_str().len().min(3)]);
        f.parse::<i64>().unwrap_or(0)
    });
    let offset = match c.get(8).map(|m| m.as_str()) {
        None | Some("Z") => 0,
        Some(z) => {
            let sign = if z.starts_with('-') { -1 } else { 1 };
            sign * (z[1..3].parse::<i64>().ok()? * 60 + z[4..6].parse::<i64>().ok()?)
        }
    };
    // Days from the civil date (the inverse of store::iso).
    let (yy, mm) = if mo <= 2 { (y - 1, mo + 9) } else { (y, mo - 3) };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let doy = (153 * mm + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 86_400 + h * 3600 + mi * 60 + se - offset * 60) * 1000 + ms) as f64)
}

#[cfg(test)]
mod tests {
    #[test]
    fn iso_round_trips() {
        for ms in [0i64, 1_800_000_000_123, 951_782_400_000, -86_400_000] {
            assert_eq!(super::parse(&crate::store::iso(ms)), Some(ms as f64));
        }
        assert_eq!(super::parse("2026-10-29T11:37:14.587000"), super::parse("2026-10-29T11:37:14.587Z"));
        assert_eq!(super::parse("2026-01-01T01:00:00+01:00"), super::parse("2026-01-01T00:00:00Z"));
        assert_eq!(super::parse("2026-02-30T00:00:00Z"), None);
        assert_eq!(super::parse("soon"), None);
    }
}
