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
  if n < 10 {
    (n + '0'.to_int()).unsafe_to_char()
  } else {
    (n - 10 + 'A'.to_int()).unsafe_to_char()
  }
}

///|
/// Percent-encode a string per RFC 3986 (everything but the unreserved
/// characters), as required for SigV4 canonical query strings. If
/// `slash_okay` is set, `/` is left unescaped (used for URI paths).
pub fn percent_encode(input : StringView, slash_okay? : Bool = false) -> String {
  let out = StringBuilder()
  for ch in input {
    if ch.is_ascii() {
      let byte = ch.to_int().to_byte()
      if is_unreserved_byte(byte) || (slash_okay && byte is b'/') {
        out.write_char(ch)
      } else {
        let n = byte.to_int()
        out.write_char('%')
        out.write_char(hex_digit(n / 16))
        out.write_char(hex_digit(n % 16))
      }
    } else {
      let bytes = @utf8.encode(ch.to_string())
      for byte in bytes {
        let n = byte.to_int()
        out.write_char('%')
        out.write_char(hex_digit(n / 16))
        out.write_char(hex_digit(n % 16))
      }
    }
  }
  out.to_string()
}

///|
/// Serialize a query map into its canonical form: keys and values
/// percent-encoded, entries sorted byte-wise by encoded key (then value).
/// Note: `String::compare` must not be used here — SigV4 requires pure
/// byte-wise lexicographic ordering.
pub fn canonical_query(query : Map[String, String]) -> String {
  let pairs = query.to_array()
  pairs.sort_by(fn(left, right) {
    let lk = percent_encode(left.0)
    let rk = percent_encode(right.0)
    let c = ascii_compare(lk, rk)
    if c == 0 {
      ascii_compare(percent_encode(left.1), percent_encode(right.1))
    } else {
      c
    }
  })
  pairs
  .map(fn(pair) { "\{percent_encode(pair.0)}=\{percent_encode(pair.1)}" })
  .join("&")
}
