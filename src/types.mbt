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
/// An HTTP request to be signed. `meth` is the request method, `path` is the
/// request-target path as sent (URI-encoded once), `query` holds the query
/// parameters exactly as they will appear on the wire — names and values
/// already RFC 3986 component-encoded (see `encode_query_component`),
/// duplicates allowed, `None` for a bare parameter without `=` — `headers`
/// are name/value pairs in any order, and `body` holds the raw payload
/// bytes.
pub(all) struct HttpRequest {
  meth : @http.RequestMethod
  path : String
  query : Array[(String, String?)]
  headers : Array[(String, String)]
  body : Bytes
} derive(Eq)

///|
/// How the payload line of the canonical request is produced:
///
/// - `Sha256` — hash `body` and use it as the payload line (generic services
///   that include the payload hash in the signature)
/// - `Empty` — the hash of the empty body as the payload line
/// - `Unsigned` — the literal `UNSIGNED-PAYLOAD` line (S3 streaming/chunked
///   uploads and shared download URLs)
/// - `Provided` — a caller-computed hash (hex, or `UNSIGNED-PAYLOAD`) as the
///   payload line
///
/// The payload line is independent of the `X-Amz-Content-Sha256` header —
/// whether that header is added is governed by `payload_checksum_kind`.
pub(all) enum PayloadHash {
  Sha256
  Empty
  Unsigned
  Provided(String)
} derive(Eq)

///|
/// Whether the `X-Amz-Content-Sha256` header is added to the signed request:
///
/// - `NoHeader` — "normal mode"; correct for every AWS service except S3
///   (the default)
/// - `XAmzSha256` — add the header carrying the resolved payload line;
///   required for S3
pub(all) enum PayloadChecksumKind {
  XAmzSha256
  NoHeader
} derive(Eq)

///|
/// How the canonical request's URI path is encoded. The request `path` is
/// assumed to be URI-encoded once, as sent:
///
/// - `Double` — re-encode `%` as `%25` (and any remaining reserved
///   characters); required by most services, which do not decode the path
///   before verifying the signature (the default)
/// - `Single` — take the path as-is; required by S3, which rejects
///   double-encoded paths
pub(all) enum PercentEncoding {
  Double
  Single
} derive(Eq)

///|
/// Request signing options: a SigV4 timestamp (`YYYYMMDDTHHMMSSZ`) and the
/// credential scope, plus behavioral switches. `normalize_path` removes
/// RFC 3986 dot segments before signing and defaults to true — correct for
/// every AWS service except S3, where object keys containing `.` / `..`
/// must survive. `omit_session_token` keeps a session token out of the
/// signature while still sending it as a request header (SigV4 conformance
/// scenarios). `excluded_headers` are excluded from the signature (matched
/// case-insensitively) but still sent with the request.
pub(all) struct SigningOptions {
  timestamp : String
  region : String
  service : String
  normalize_path : Bool
  percent_encoding : PercentEncoding
  payload_hash : PayloadHash
  payload_checksum_kind : PayloadChecksumKind
  omit_session_token : Bool
  excluded_headers : Array[String]
} derive(Eq)

///|
/// Headers excluded from signing by default: calculated by the signer
/// itself, altered by proxies, or request-independent. Mirrors the
/// exclusion sets used by the Go, Java, JS and Rust AWS SDKs. Excluded
/// headers are still sent with the request.
fn default_excluded_headers() -> Array[String] {
  [
    "authorization", "user-agent", "x-amzn-trace-id", "expect", "transfer-encoding",
  ]
}

///|
pub fn SigningOptions::SigningOptions(
  timestamp~ : String,
  region~ : String,
  service~ : String,
  normalize_path? : Bool = true,
  percent_encoding? : PercentEncoding = Double,
  payload_hash? : PayloadHash = Sha256,
  payload_checksum_kind? : PayloadChecksumKind = NoHeader,
  omit_session_token? : Bool = false,
  excluded_headers? : Array[String] = default_excluded_headers(),
) -> SigningOptions {
  {
    timestamp,
    region,
    service,
    normalize_path,
    percent_encoding,
    payload_hash,
    payload_checksum_kind,
    omit_session_token,
    excluded_headers,
  }
}

///|
/// Signing options for S3 and S3-compatible providers (MinIO, Cloudflare
/// R2, Backblaze B2, Wasabi, DigitalOcean Spaces, ...): paths are taken
/// exactly as sent (no dot-segment normalization, no re-encoding) and the
/// `X-Amz-Content-Sha256` header is added, as the S3 API requires.
/// `service` defaults to `"s3"`, the signing name used by every
/// S3-compatible provider; `region` is provider-specific (e.g.
/// `"us-east-1"` for AWS, `"auto"` for R2, the server-configured region for
/// MinIO).
pub fn SigningOptions::for_s3(
  timestamp~ : String,
  region~ : String,
  service? : String = "s3",
  payload_hash? : PayloadHash = Sha256,
  omit_session_token? : Bool = false,
  excluded_headers? : Array[String] = default_excluded_headers(),
) -> SigningOptions {
  SigningOptions::SigningOptions(
    timestamp~,
    region~,
    service~,
    normalize_path=false,
    percent_encoding=Single,
    payload_hash~,
    payload_checksum_kind=XAmzSha256,
    omit_session_token~,
    excluded_headers~,
  )
}

///|
/// The canonical-layer intermediates of a SigV4 signing operation, exposed
/// for debugging and for algorithms that share the canonical layer (e.g.
/// SigV4a). `canonical_request` is the `\n`-joined creq string,
/// `string_to_sign` the `AWS4-HMAC-SHA256` sts string built from it, and
/// `signed_headers` / `payload_hash` the `SignedHeaders=` value and resolved
/// canonical payload line. For header signing the creq is built from the
/// request's signing headers; for query signing, from the headers that will
/// ride in the URL.
pub(all) struct CanonicalParts {
  canonical_request : String
  string_to_sign : String
  signed_headers : String
  payload_hash : String
} derive(Eq)

///|
/// The result of signing a request with the SigV4 query-string auth variant.
/// `url` is the fully signed URL. `signed_headers` is the `SignedHeaders=`
/// value (semicolon-joined, lowercase header names): every header listed
/// there must be sent verbatim with the request for the signature to
/// verify.
pub(all) struct PresignedUrl {
  url : String
  signed_headers : String
} derive(Eq)
