///|
fn sha256_hex(data : String) -> String {
  @crypto.bytes_to_hex_string(@crypto.sha256(@utf8.encode(data)))
}

///|
fn sha256_bytes_hex(data : Bytes) -> String {
  @crypto.bytes_to_hex_string(@crypto.sha256(data))
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
  secret~ : String,
  date~ : String,
  region~ : String,
  service~ : String,
) -> Bytes {
  let k_date = hmac_sha256(@utf8.encode("AWS4\{secret}"), date)
  let k_region = hmac_sha256(k_date.unsafe_reinterpret_as_bytes(), region)
  let k_service = hmac_sha256(k_region.unsafe_reinterpret_as_bytes(), service)
  hmac_sha256(k_service.unsafe_reinterpret_as_bytes(), "aws4_request").unsafe_reinterpret_as_bytes()
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
fn canonical_header_pairs(pairs : Array[(String, String)]) -> (String, String) {
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
fn canonical_headers_of(headers : Array[(String, String)]) -> (String, String) {
  canonical_header_pairs(
    headers.map(fn(pair) { (pair.0.to_lower(), normalize_header_value(pair.1)) }),
  )
}

///|
/// The canonical-request payload line for each payload-hash mode.
fn payload_hash_line(body : Bytes, payload_hash~ : PayloadHash) -> String {
  match payload_hash {
    Sha256 => sha256_bytes_hex(body)
    Empty => sha256_bytes_hex(@utf8.encode(""))
    Unsigned => "UNSIGNED-PAYLOAD"
    Provided(hash) => hash
  }
}

///|
/// Set `name` to `value` on a copy of `headers`: existing entries with the
/// same (case-insensitive) name are replaced in place, otherwise the header
/// is appended.
fn upsert_header(
  headers : Array[(String, String)],
  name : String,
  value : String,
) -> Array[(String, String)] {
  let lower = name.to_lower()
  if headers.any(fn(header) { header.0.to_lower() == lower }) {
    headers.map(fn(header) {
      if header.0.to_lower() == lower {
        (header.0, value)
      } else {
        header
      }
    })
  } else {
    let out = headers.copy()
    out.push((name, value))
    out
  }
}

///|
/// The headers that will be sent with the request: the originals plus
/// `X-Amz-Date`, plus `X-Amz-Content-Sha256` when `payload_checksum_kind`
/// is `XAmzSha256`, plus `X-Amz-Security-Token` when a session token is
/// present and not omitted.
fn prepare_headers(
  request : HttpRequest,
  credentials : Credentials,
  options : SigningOptions,
  payload_line : String,
) -> Array[(String, String)] {
  let with_date = upsert_header(
    request.headers,
    "X-Amz-Date",
    options.timestamp,
  )
  let with_body = if options.payload_checksum_kind is XAmzSha256 {
    upsert_header(with_date, "X-Amz-Content-Sha256", payload_line)
  } else {
    with_date
  }
  match (credentials.session_token, options.omit_session_token) {
    (Some(token), false) =>
      upsert_header(with_body, "X-Amz-Security-Token", token)
    _ => with_body
  }
}

///|
/// The subset of the given headers that participate in the signature:
/// headers named in `options.excluded_headers` are dropped (they are still
/// sent with the request), as is `X-Amz-Security-Token` when
/// `omit_session_token` is set.
fn headers_for_signing(
  headers : Array[(String, String)],
  credentials : Credentials,
  options : SigningOptions,
) -> Array[(String, String)] {
  let omit_token = credentials.session_token is Some(_) &&
    options.omit_session_token
  headers.filter(fn(header) {
    let name = header.0.to_lower()
    let token_ok = name != "x-amz-security-token" || !omit_token
    let excluded = options.excluded_headers
      .iter()
      .any(fn(pattern) { pattern.to_lower() == name })
    token_ok && !excluded
  })
}

///|
/// Render a `@http.RequestMethod` as the uppercase verb used on the
/// canonical request line.
fn method_to_string(meth : @http.RequestMethod) -> String {
  match meth {
    Get => "GET"
    Head => "HEAD"
    Post => "POST"
    Put => "PUT"
    Delete => "DELETE"
    Connect => "CONNECT"
    Options => "OPTIONS"
    Trace => "TRACE"
    Patch => "PATCH"
  }
}

///|
/// Build the `AWS4-HMAC-SHA256` string-to-sign from a canonical request.
fn build_string_to_sign(
  canonical_request~ : String,
  timestamp~ : String,
  region~ : String,
  service~ : String,
) -> String {
  let date = timestamp[:8].to_owned()
  let scope = "\{date}/\{region}/\{service}/aws4_request"
  ["AWS4-HMAC-SHA256", timestamp, scope, sha256_hex(canonical_request)].join(
    "\n",
  )
}

///|
/// Compute the canonical-layer intermediates for header signing: the
/// canonical request and string-to-sign built from the request's signing
/// headers (the prepared headers minus any session token excluded by
/// `omit_session_token`), the `SignedHeaders=` value, and the resolved
/// payload line.
pub fn canonical_parts(
  request~ : HttpRequest,
  credentials~ : Credentials,
  options~ : SigningOptions,
) -> CanonicalParts {
  let payload_line = payload_hash_line(
    request.body,
    payload_hash=options.payload_hash,
  )
  let signing_headers = headers_for_signing(
    prepare_headers(request, credentials, options, payload_line),
    credentials,
    options,
  )
  let (canonical_headers, signed_headers) = canonical_headers_of(
    signing_headers,
  )
  let canonical_request = [
    method_to_string(request.meth),
    canonical_uri(
      request.path,
      normalize=options.normalize_path,
      percent_encoding=options.percent_encoding,
    ),
    canonical_query_string(request.query),
    canonical_headers,
    signed_headers,
    payload_line,
  ].join("\n")
  {
    canonical_request,
    string_to_sign: build_string_to_sign(
      canonical_request~,
      timestamp=options.timestamp,
      region=options.region,
      service=options.service,
    ),
    signed_headers,
    payload_hash: payload_line,
  }
}

///|
/// Sign an HTTP request with AWS Signature Version 4 and return a new
/// request ready to send as-is: the query parameters sorted into canonical
/// order (render the wire form with `canonical_query_string`), the signing
/// headers applied — `X-Amz-Date`, plus `X-Amz-Content-Sha256` when
/// `payload_checksum_kind` is `XAmzSha256`, plus `X-Amz-Security-Token` when
/// a session token is present and not omitted — and finally the computed
/// `Authorization` header, which replaces any caller-supplied `Authorization`
/// header. Headers named in `excluded_headers` are sent but not signed.
pub fn sign(
  request : HttpRequest,
  credentials : Credentials,
  options : SigningOptions,
) -> HttpRequest {
  let parts = canonical_parts(request~, credentials~, options~)
  let signature = hmac_sha256_hex(
    signing_key(
      secret=credentials.secret_access_key,
      date=options.timestamp[:8].to_owned(),
      region=options.region,
      service=options.service,
    ),
    parts.string_to_sign,
  )
  // drop any caller-supplied Authorization header so the computed one is
  // the only one on the signed request
  let prepared = prepare_headers(
    request,
    credentials,
    options,
    parts.payload_hash,
  ).filter(fn(header) { header.0.to_lower() != "authorization" })
  let date = options.timestamp[:8].to_owned()
  let scope = "\{date}/\{options.region}/\{options.service}/aws4_request"
  let final_headers = prepared.copy()
  if credentials.session_token is Some(token) && options.omit_session_token {
    final_headers.push(("X-Amz-Security-Token", token))
  }
  final_headers.push(
    (
      "Authorization",
      "AWS4-HMAC-SHA256 Credential=\{credentials.access_key_id}/\{scope}, SignedHeaders=\{parts.signed_headers}, Signature=\{signature}",
    ),
  )
  { ..request, query: sorted_query(request.query), headers: final_headers, }
}

///|
/// Sign a request with the SigV4 query-string auth variant and return the
/// fully signed URL together with the `SignedHeaders` value: every header
/// listed in `signed_headers` (semicolon-joined, lowercase names) must be
/// sent verbatim with the request for the signature to verify. Headers named
/// in `excluded_headers` are never signed.
///
/// The auth components (`X-Amz-Algorithm`, `X-Amz-Credential`,
/// `X-Amz-Date`, `X-Amz-Expires`, `X-Amz-SignedHeaders`,
/// `X-Amz-Security-Token` when present, and `X-Amz-Signature`) land in the
/// URL query string rather than headers.
///
/// The payload line follows `options.payload_hash`; shared-download URLs
/// conventionally use `Unsigned`, while signing a request against a known
/// body uses `Sha256` or `Provided`.
///
/// Raises if `request.headers` has no `Host` header.
///
/// `expires` is bounded by SigV4 to `[1, 604800]` (1 second to 7 days); the
/// bound is not enforced here — AWS rejects out-of-range values server-side.
/// Existing `query` entries are taken as sent and merged with the auth
/// params.
/// `scheme` defaults to `https` (use e.g. `wss` for WebSocket endpoints).
pub fn presign_url(
  request~ : HttpRequest,
  credentials~ : Credentials,
  options~ : SigningOptions,
  expires~ : Int,
  scheme? : String = "https",
) -> PresignedUrl raise {
  let host = match
    request.headers.filter(fn(header) { header.0.to_lower() == "host" }) {
    [(_, value), ..] => value
    _ =>
      fail(
        "presign_url requires a Host header in request.headers (the signed URL and the signature are both derived from it)",
      )
  }
  let date = options.timestamp[:8].to_owned()
  let scope = "\{date}/\{options.region}/\{options.service}/aws4_request"
  let (canonical_headers, signed_headers) = canonical_headers_of(
    headers_for_signing(request.headers, credentials, options),
  )
  let auth_params : Array[(String, String?)] = [
    ("X-Amz-Algorithm", Some("AWS4-HMAC-SHA256")),
    (
      "X-Amz-Credential",
      Some(encode_query_component("\{credentials.access_key_id}/\{scope}")),
    ),
    ("X-Amz-Date", Some(options.timestamp)),
    ("X-Amz-Expires", Some(expires.to_string())),
    ("X-Amz-SignedHeaders", Some(encode_query_component(signed_headers))),
  ]
  // A session token either joins the signed auth params or rides in the URL
  // after the signature, unsigned (same semantics as header signing).
  let unsigned_token : String? = match
    (credentials.session_token, options.omit_session_token) {
    (Some(token), false) => {
      auth_params.push(
        ("X-Amz-Security-Token", Some(encode_query_component(token))),
      )
      None
    }
    (Some(token), true) => Some(token)
    (None, _) => None
  }
  let uri = canonical_uri(
    request.path,
    normalize=options.normalize_path,
    percent_encoding=options.percent_encoding,
  )
  let query = canonical_query_string(request.query + auth_params)
  let canonical_request = [
    method_to_string(request.meth),
    uri,
    query,
    canonical_headers,
    signed_headers,
    payload_hash_line(request.body, payload_hash=options.payload_hash),
  ].join("\n")
  let string_to_sign = build_string_to_sign(
    canonical_request~,
    timestamp=options.timestamp,
    region=options.region,
    service=options.service,
  )
  let signature = hmac_sha256_hex(
    signing_key(
      secret=credentials.secret_access_key,
      date=options.timestamp[:8].to_owned(),
      region=options.region,
      service=options.service,
    ),
    string_to_sign,
  )
  let url = "\{scheme}://\{host}\{uri}?\{query}&X-Amz-Signature=\{signature}"
  {
    url: match unsigned_token {
      Some(token) =>
        url + "&X-Amz-Security-Token=" + encode_query_component(token)
      None => url
    },
    signed_headers,
  }
}
