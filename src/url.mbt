///|
fn ascii_compare(left : String, right : String) -> Int {
  let min_len = Int::min(left.length(), right.length())
  for i in 0..<min_len {
    let diff = left[i].to_int() - right[i].to_int()
    if diff != 0 {
      return diff
    }
  }
  left.length() - right.length()
}

///|
fn is_unreserved_byte(byte : Byte) -> Bool {
  let n = byte.to_int()
  (n >= 65 && n <= 90) ||
  (n >= 97 && n <= 122) ||
  (n >= 48 && n <= 57) ||
  byte is b'-' ||
  byte is b'_' ||
  byte is b'.' ||
  byte is b'~'
}

///|
fn hex_digit(n : Int) -> Char {
  // `n` is always 0..15 at the call sites
  let ch = @uri.int_to_hex(n).unwrap_or('0')
  if ch >= 'a' && ch <= 'f' {
    (ch.to_int() - 32).unsafe_to_char()
  } else {
    ch
  }
}

///|
/// RFC 3986 percent-encoding over the UTF-8 bytes of `s`: a byte survives
/// only if it is an unreserved character (or `/` when `keep_slash` is set).
/// Encoding bytes rather than chars gives non-ASCII characters their UTF-8
/// percent-escapes, as SigV4 canonicalization requires.
fn percent_encode_utf8(input : String, keep_slash~ : Bool) -> String {
  let out = StringBuilder()
  for byte in @utf8.encode(input) {
    let n = byte.to_int()
    if is_unreserved_byte(byte) || (keep_slash && byte is b'/') {
      out.write_char(n.unsafe_to_char())
    } else {
      out.write_char('%')
      out.write_char(hex_digit(n / 16))
      out.write_char(hex_digit(n % 16))
    }
  }
  out.to_string()
}

///|
/// Percent-encode a URI query component per RFC 3986: only unreserved
/// characters survive, everything else (non-ASCII as UTF-8) is escaped.
/// This is the encoding the canonical query string uses, so components
/// encoded here are byte-identical to their canonical form.
pub fn encode_query_component(s : String) -> String {
  percent_encode_utf8(s, keep_slash=false)
}

///|
/// Percent-encode a URI path for a canonical request line: unreserved
/// characters survive, `/` separators pass through, non-ASCII characters
/// encode as UTF-8. Applied to paths that already carry percent-escapes,
/// this re-encodes them (`%` becomes `%25`), i.e. `PercentEncoding::Double`.
pub fn percent_encode_path(s : String) -> String {
  percent_encode_utf8(s, keep_slash=true)
}

///|
/// Canonical URI: RFC 3986 dot-segment removal (when requested) followed by
/// percent encoding per `percent_encoding`. The `Double`/`normalize_path`
/// pairing is correct for every AWS service except S3, which needs
/// `Single`/`normalize_path=false` so object keys survive untouched.
fn canonical_uri(
  path : String,
  normalize~ : Bool,
  percent_encoding~ : PercentEncoding,
) -> String {
  let base = if normalize {
    let normalized = @uri.normalize_path(path)
    // `normalize_path` drops a trailing empty segment; the canonical URI
    // keeps it (e.g. `/a/` stays `/a/`).
    if path.has_suffix("/") && path != "/" && !normalized.has_suffix("/") {
      "\{normalized}/"
    } else {
      normalized
    }
  } else {
    path
  }
  match percent_encoding {
    Double => percent_encode_path(base)
    Single => base
  }
}

///|
/// Sort query parameters into canonical order: byte-wise by encoded name,
/// then by encoded value (a bare parameter counts as an empty value).
/// Returns a sorted copy; the input is untouched.
fn sorted_query(params : Array[(String, String?)]) -> Array[(String, String?)] {
  let pairs = params.copy()
  pairs.sort_by(fn(left, right) {
    let by_name = ascii_compare(left.0, right.0)
    if by_name == 0 {
      let left_value = match left.1 {
        Some(v) => v
        None => ""
      }
      let right_value = match right.1 {
        Some(v) => v
        None => ""
      }
      ascii_compare(left_value, right_value)
    } else {
      by_name
    }
  })
  pairs
}

///|
/// Render query parameters as the canonical query string: the parameters
/// must already be RFC 3986 component-encoded exactly as they will appear
/// on the wire (use `encode_query_component`); this sorts them byte-wise by
/// encoded name then value and joins `name=value` pairs with `&` (a bare
/// parameter without `=` canonicalizes to `name=`). The result is
/// byte-identical to the query line the signer computes the signature over.
pub fn canonical_query_string(params : Array[(String, String?)]) -> String {
  sorted_query(params)
  .map(fn(param) {
    match param.1 {
      Some(value) => "\{param.0}=\{value}"
      None => "\{param.0}="
    }
  })
  .join("&")
}
