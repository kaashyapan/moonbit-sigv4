///|
pub(all) struct Credentials {
  access_key_id : String
  secret_access_key : String
  session_token : String?
} derive(Eq)

///|
pub fn Credentials::Credentials(
  access_key_id : String,
  secret_access_key : String,
  session_token? : String,
) -> Credentials {
  { access_key_id, secret_access_key, session_token, }
}

///|
fn sha256_hex(data : String) -> String {
  @crypto.bytes_to_hex_string(@crypto.sha256(@utf8.encode(data)))
}

///|
fn hmac_sha256(key : BytesView, data : String) -> FixedArray[Byte] {
  @crypto.hmac(@crypto.SHA256::new(), key, @utf8.encode(data))
}

///|
fn hmac_sha256_hex(key : BytesView, data : String) -> String {
  @crypto.bytes_to_hex_string(hmac_sha256(key, data))
}

///|
/// Derive the SigV4 signing key for the given date, region and service.
pub fn signing_key(
  secret : String,
  date : String,
  region : String,
  service : String,
) -> FixedArray[Byte] {
  let k_date = hmac_sha256(@utf8.encode("AWS4\{secret}"), date)
  let k_region = hmac_sha256(k_date.unsafe_reinterpret_as_bytes(), region)
  let k_service = hmac_sha256(k_region.unsafe_reinterpret_as_bytes(), service)
  hmac_sha256(k_service.unsafe_reinterpret_as_bytes(), "aws4_request")
}

///|
fn normalize_header_value(value : String) -> String {
  let out = StringBuilder()
  let mut in_whitespace = false
  for ch in value.trim() {
    if ch.is_ascii_whitespace() {
      if !in_whitespace {
        out.write_char(' ')
        in_whitespace = true
      }
    } else {
      out.write_char(ch)
      in_whitespace = false
    }
  }
  out.to_string()
}

///|
fn canonical_headers(headers : Map[String, String]) -> (String, String) {
  let pairs : Array[(String, String)] = []
  for key, value in headers {
    pairs.push((key.to_lower(), normalize_header_value(value)))
  }
  pairs.sort_by(fn(left, right) { ascii_compare(left.0, right.0) })
  let coalesced : Array[(String, Array[String])] = []
  for pair in pairs {
    let (name, value) = pair
    match coalesced.last() {
      Some((last_name, values)) if last_name == name => values.push(value)
      _ => coalesced.push((name, [value]))
    }
  }
  let canonical = coalesced
    .map(fn(pair) { "\{pair.0}:\{pair.1.join(",")}\n" })
    .join("")
  let signed = coalesced.map(fn(pair) { pair.0 }).join(";")
  (canonical, signed)
}

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
/// Sign a request with AWS Signature Version 4 and return the headers to send,
/// including the `Authorization` header. The request method is given as an
/// uppercase HTTP verb (e.g. `"GET"`), `path` must already be the canonical
/// URI path, and `payload_hash` is the hex SHA-256 of the body (or
/// `"UNSIGNED-PAYLOAD"`).
pub fn sign_headers(
  meth : String,
  path : String,
  query : Map[String, String],
  headers : Map[String, String],
  payload_hash : String,
  credentials : Credentials,
  region : String,
  service : String,
  timestamp : String,
) -> Map[String, String] {
  let date = timestamp[:8].to_owned()
  let (canonical, signed_headers) = canonical_headers(headers)
  let canonical_request = [
    meth,
    path,
    canonical_query(query),
    canonical,
    signed_headers,
    payload_hash,
  ].join("\n")
  let scope = "\{date}/\{region}/\{service}/aws4_request"
  let string_to_sign = [
    "AWS4-HMAC-SHA256",
    timestamp,
    scope,
    sha256_hex(canonical_request),
  ].join("\n")
  let signature = hmac_sha256_hex(
    signing_key(credentials.secret_access_key, date, region, service).unsafe_reinterpret_as_bytes(),
    string_to_sign,
  )
  let signed = headers.copy()
  signed["Authorization"] = "AWS4-HMAC-SHA256 Credential=\{credentials.access_key_id}/\{scope}, SignedHeaders=\{signed_headers}, Signature=\{signature}"
  signed
}

///|
/// Build the query parameters of a presigned URL: the `X-Amz-*` authorization
/// parameters plus the computed `X-Amz-Signature`. The payload is always
/// treated as `UNSIGNED-PAYLOAD`, as required for presigned URLs. Only `host`
/// plus the names in `signed_headers` are included in the signature; the
/// caller is responsible for sending those headers verbatim with the request.
pub fn presign_query(
  meth : String,
  path : String,
  host : String,
  credentials : Credentials,
  region : String,
  service : String,
  timestamp : String,
  expires : Int,
  signed_headers? : Map[String, String] = {},
) -> Map[String, String] {
  let date = timestamp[:8].to_owned()
  let scope = "\{date}/\{region}/\{service}/aws4_request"
  let query : Map[String, String] = Map([])
  query["X-Amz-Algorithm"] = "AWS4-HMAC-SHA256"
  query["X-Amz-Credential"] = "\{credentials.access_key_id}/\{scope}"
  query["X-Amz-Date"] = timestamp
  query["X-Amz-Expires"] = expires.to_string()
  let headers = Map([])
  headers["host"] = host
  for key, value in signed_headers {
    headers[key] = value
  }
  let (canonical, signed) = canonical_headers(headers)
  if credentials.session_token is Some(token) {
    query["X-Amz-Security-Token"] = token
  }
  query["X-Amz-SignedHeaders"] = signed
  let canonical_request = [
    meth,
    path,
    canonical_query(query),
    canonical,
    signed,
    "UNSIGNED-PAYLOAD",
  ].join("\n")
  let string_to_sign = [
    "AWS4-HMAC-SHA256",
    timestamp,
    scope,
    sha256_hex(canonical_request),
  ].join("\n")
  let signature = hmac_sha256_hex(
    signing_key(credentials.secret_access_key, date, region, service).unsafe_reinterpret_as_bytes(),
    string_to_sign,
  )
  query["X-Amz-Signature"] = signature
  query
}
