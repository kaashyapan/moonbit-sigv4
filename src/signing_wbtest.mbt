///|
test "canonical parts expose the AWS documentation intermediates" {
  let parts = canonical_parts(
    request={
      meth: @http.Get,
      path: "/test.txt",
      query: [],
      headers: [
        ("Host", "examplebucket.s3.amazonaws.com"),
        ("Range", "bytes=0-9"),
      ],
      body: b"",
    },
    credentials=test_credentials(),
    options=SigningOptions::for_s3(
      timestamp="20130524T000000Z",
      region="us-east-1",
    ),
  )
  assert_eq(
    parts.canonical_request,
    "GET\n/test.txt\n\nhost:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\nx-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nx-amz-date:20130524T000000Z\n\nhost;range;x-amz-content-sha256;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
  assert_eq(
    parts.string_to_sign,
    "AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972",
  )
  assert_eq(parts.signed_headers, "host;range;x-amz-content-sha256;x-amz-date")
}

///|
test "sign reproduces the AWS SigV4 documentation example" {
  let signed = sign(
    {
      meth: @http.Get,
      path: "/test.txt",
      query: [],
      headers: [
        ("Host", "examplebucket.s3.amazonaws.com"),
        ("Range", "bytes=0-9"),
      ],
      body: b"",
    },
    test_credentials(),
    SigningOptions::for_s3(timestamp="20130524T000000Z", region="us-east-1"),
  )
  guard! signed.headers.last() is Some(("Authorization", auth))
  assert_eq(
    auth, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=67fe34c8530db585abddc51067328adfedb6e42487d2566dc7d927d6e2722900",
  )
}

///|
test "sign normalizes paths and canonicalizes query strings" {
  let signed = sign(
    {
      meth: @http.Get,
      path: "/a/./b/../c%20d/",
      query: [
        ("b", Some("2")),
        ("a", Some("1")),
        ("a", Some("0")),
        ("key", None),
      ],
      headers: [("host", "example.amazonaws.com")],
      body: b"",
    },
    test_credentials(),
    SigningOptions(
      timestamp="20130524T000000Z",
      region="us-east-1",
      service="service",
      payload_hash=Empty,
    ),
  )
  guard! signed.headers.last() is Some(("Authorization", auth))
  assert_eq(
    auth, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=2121e9cf9d6d9ee2d96212f89b1a4caf0c687909332d8a534dee567b863cd2be",
  )
}

///|
test "sign returns the canonicalized query ready to send" {
  let signed = sign(
    {
      meth: @http.Get,
      path: "/",
      query: [
        ("b", Some("2")),
        ("a", Some("1")),
        ("a", Some("0")),
        ("key", None),
      ],
      headers: [("host", "example.amazonaws.com")],
      body: b"",
    },
    test_credentials(),
    SigningOptions(
      timestamp="20130524T000000Z",
      region="us-east-1",
      service="service",
      payload_hash=Empty,
    ),
  )
  // sorted by encoded name then value, bare parameter -> ("key", None)
  assert_eq(signed.query, [
    ("a", Some("0")),
    ("a", Some("1")),
    ("b", Some("2")),
    ("key", None),
  ])
}

///|
test "sign includes the session token in the signature" {
  let credentials = Credentials(
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    session_token="SESSIONTOKEN",
  )
  let signed = sign(
    {
      meth: @http.Get,
      path: "/",
      query: [],
      headers: [("Host", "example.amazonaws.com")],
      body: b"",
    },
    credentials,
    SigningOptions(
      timestamp="20130524T000000Z",
      region="us-east-1",
      service="service",
      payload_checksum_kind=XAmzSha256,
    ),
  )
  guard! signed.headers.last() is Some(("Authorization", auth))
  assert_eq(
    auth, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=7ac73971fddde6db27cd9f4d8477cc3d75a315659d92c50b48e94d8422255bee",
  )
}

///|
test "sign omits the session token from the signature when asked" {
  let credentials = Credentials(
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    session_token="SESSIONTOKEN",
  )
  let signed = sign(
    {
      meth: @http.Get,
      path: "/",
      query: [],
      headers: [("Host", "example.amazonaws.com")],
      body: b"",
    },
    credentials,
    SigningOptions(
      timestamp="20130524T000000Z",
      region="us-east-1",
      service="service",
      payload_hash=Empty,
      omit_session_token=true,
    ),
  )
  guard! signed.headers.last() is Some(("Authorization", auth))
  assert_eq(
    auth, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=6b52c88578c3a6e09e219aaa1b56c53f15bc2ad1a7d2bc31287ecaf19c2d2174",
  )
  // the token still rides along as a (unsigned) request header
  assert_true(
    signed.headers.any(fn(header) {
      header is ("X-Amz-Security-Token", "SESSIONTOKEN")
    }),
  )
}

///|
test "percent encoding escapes non-ASCII as UTF-8" {
  assert_eq(encode_query_component("文件 a"), "%E6%96%87%E4%BB%B6%20a")
  assert_eq(
    percent_encode_path("/文档/test.txt"),
    "/%E6%96%87%E6%A1%A3/test.txt",
  )
}

///|
test "canonical encoders treat percent as a literal (no triplet passthrough)" {
  // unlike `@uri.percent_encode`, which passes valid %XX triplets through,
  // the canonical encoders take their input as raw values: a literal `%`
  // must be escaped so that `PercentEncoding::Double` re-encodes
  // already-encoded paths, and raw query values like "100%" stay literal
  assert_eq(encode_query_component("100%"), "100%25")
  assert_eq(encode_query_component("a%20b"), "a%2520b")
  assert_eq(percent_encode_path("/a%20b"), "/a%2520b")
}

///|
test "percent encoding Single keeps pre-encoded paths intact" {
  // S3-style: normalize_path=false + Single leaves the path exactly as sent.
  let single = canonical_parts(
    request={
      meth: @http.Get,
      path: "/a%20b",
      query: [],
      headers: [("host", "example.amazonaws.com")],
      body: b"",
    },
    credentials=test_credentials(),
    options=SigningOptions(
      timestamp="20130524T000000Z",
      region="us-east-1",
      service="s3",
      normalize_path=false,
      percent_encoding=Single,
      payload_hash=Empty,
    ),
  )
  assert_eq(
    single.canonical_request,
    "GET\n/a%20b\n\nhost:example.amazonaws.com\nx-amz-date:20130524T000000Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
  // Default Double re-encodes the %: most services require this.
  let double = canonical_parts(
    request={
      meth: @http.Get,
      path: "/a%20b",
      query: [],
      headers: [("host", "example.amazonaws.com")],
      body: b"",
    },
    credentials=test_credentials(),
    options=SigningOptions(
      timestamp="20130524T000000Z",
      region="us-east-1",
      service="service",
      payload_hash=Empty,
    ),
  )
  assert_true(double.canonical_request.has_prefix("GET\n/a%2520b\n"))
}

///|
test "content-sha256 header is omitted by default for generic services" {
  let parts = canonical_parts(
    request={
      meth: @http.Post,
      path: "/",
      query: [],
      headers: [("host", "dynamodb.us-east-1.amazonaws.com")],
      body: b"",
    },
    credentials=test_credentials(),
    options=SigningOptions(
      timestamp="20130524T000000Z",
      region="us-east-1",
      service="dynamodb",
    ),
  )
  // payload hash still signs the body, but no x-amz-content-sha256 header
  assert_eq(parts.signed_headers, "host;x-amz-date")
  assert_true(
    parts.canonical_request.contains(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
  )
  assert_true(!parts.canonical_request.contains("x-amz-content-sha256"))
}

///|
test "excluded headers are sent but not signed" {
  let signed = sign(
    {
      meth: @http.Get,
      path: "/",
      query: [],
      headers: [
        ("Host", "example.amazonaws.com"),
        ("User-Agent", "test-agent"),
        ("Expect", "100-continue"),
        ("X-Amzn-Trace-Id", "trace-1"),
      ],
      body: b"",
    },
    test_credentials(),
    SigningOptions(
      timestamp="20130524T000000Z",
      region="us-east-1",
      service="service",
      payload_hash=Empty,
    ),
  )
  // excluded headers still ride on the signed request...
  assert_true(
    signed.headers.any(fn(header) { header is ("User-Agent", "test-agent") }),
  )
  assert_true(
    signed.headers.any(fn(header) { header is ("Expect", "100-continue") }),
  )
  // ...but only host and x-amz-date participate in the signature
  guard! signed.headers.last() is Some(("Authorization", auth))
  assert_true(auth.contains("SignedHeaders=host;x-amz-date"))
}
