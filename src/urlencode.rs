/// RFC 3986 percent-encoding for a single path segment or query value. Escapes everything
/// outside the unreserved set (ALPHA / DIGIT / "-" / "." / "_" / "~") — anything else,
/// including `&`, `=`, `?`, `#`, and `/`, gets percent-encoded so callers can't inject
/// extra path segments or query parameters through user-controlled input.
pub fn urlencode(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
                vec![c]
            } else {
                format!("%{:02X}", c as u32).chars().collect()
            }
        })
        .collect()
}
