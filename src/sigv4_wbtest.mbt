///|
fn test_credentials() -> Credentials {
  Credentials(
    "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
  )
}

///|
test "sha256 empty payload" {
  assert_eq(
    sha256_hex(""),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
}

///|
test "hmac sha256 helper" {
  assert_eq(
    hmac_sha256_hex(b"key", "The quick brown fox jumps over the lazy dog"),
    "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
  )
}

///|
test "sigv4 header normalization collapses internal whitespace" {
  assert_eq(
    normalize_header_value(" \t alpha \t  beta   gamma \t "),
    "alpha beta gamma",
  )
}

///|
test "sigv4 canonical headers coalesce duplicate casing" {
  let (canonical, signed) = canonical_headers_of([
    ("Content-Type", " text/plain "),
    ("content-type", " application/json "),
    ("X-Amz-Meta-Test", " one \t two "),
  ])
  assert_eq(
    canonical, "content-type:text/plain,application/json\nx-amz-meta-test:one two\n",
  )
  assert_eq(signed, "content-type;x-amz-meta-test")
}

///|
test "presign url follows sigv4 query signing" {
  let presigned = presign_url(
    request={
      meth: @http.Get,
      path: "/test.txt",
      query: [],
      headers: [("Host", "examplebucket.s3.amazonaws.com")],
      body: b"",
    },
    credentials=test_credentials(),
    options=SigningOptions(
      timestamp="20130524T000000Z",
      region="us-east-1",
      service="s3",
      payload_hash=Unsigned,
    ),
    expires=86400,
  )
  assert_eq(
    presigned.url,
    "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=3ed0be64024db54d5574a27da223529635c383f911f80e636f0ccc13890053d2",
  )
}

///|
test "presign url honors a custom scheme" {
  let presigned = presign_url(
    request={
      meth: @http.Get,
      path: "/test.txt",
      query: [],
      headers: [("Host", "examplebucket.s3.amazonaws.com")],
      body: b"",
    },
    credentials=test_credentials(),
    options=SigningOptions(
      timestamp="20130524T000000Z",
      region="us-east-1",
      service="s3",
      payload_hash=Unsigned,
    ),
    expires=86400,
    scheme="wss",
  )
  assert_true(
    presigned.url.has_prefix("wss://examplebucket.s3.amazonaws.com/test.txt?"),
  )
  assert_true(
    presigned.url.contains(
      "X-Amz-Signature=3ed0be64024db54d5574a27da223529635c383f911f80e636f0ccc13890053d2",
    ),
  )
}

///|
test "presign url signs extra headers when present" {
  let presigned = presign_url(
    request={
      meth: @http.Put,
      path: "/test.txt",
      query: [],
      headers: [
        ("Host", "examplebucket.s3.amazonaws.com"),
        ("Content-Type", "text/plain"),
      ],
      body: b"",
    },
    credentials=test_credentials(),
    options=SigningOptions(
      timestamp="20130524T000000Z",
      region="us-east-1",
      service="s3",
      payload_hash=Unsigned,
    ),
    expires=3600,
  )
  assert_true(presigned.url.contains("X-Amz-SignedHeaders=content-type%3Bhost"))
  assert_eq(
    presigned.url,
    "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=content-type%3Bhost&X-Amz-Signature=5f25b0b81987127dd98d94e3585f8aac156b84f8c6b40e61a03c7c7e0568c328",
  )
}

///|
test "presign url includes the session token in the signature" {
  let presigned = presign_url(
    request={
      meth: @http.Get,
      path: "/test.txt",
      query: [],
      headers: [("Host", "examplebucket.s3.amazonaws.com")],
      body: b"",
    },
    credentials=Credentials(
      "AKIAIOSFODNN7EXAMPLE",
      "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
      session_token="session-token",
    ),
    options=SigningOptions(
      timestamp="20130524T000000Z",
      region="us-east-1",
      service="s3",
      payload_hash=Unsigned,
    ),
    expires=3600,
  )
  assert_eq(
    presigned.url,
    "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=3600&X-Amz-Security-Token=session-token&X-Amz-SignedHeaders=host&X-Amz-Signature=9d82ad3d00c67963b3126c325bd6421abe6445c866c20d64152bbf513ecc0fbe",
  )
}

///|
test "presign url omits the session token from the signature when asked" {
  let presigned = presign_url(
    request={
      meth: @http.Get,
      path: "/test.txt",
      query: [],
      headers: [("Host", "examplebucket.s3.amazonaws.com")],
      body: b"",
    },
    credentials=Credentials(
      "AKIAIOSFODNN7EXAMPLE",
      "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
      session_token="session-token",
    ),
    options=SigningOptions(
      timestamp="20130524T000000Z",
      region="us-east-1",
      service="s3",
      payload_hash=Unsigned,
      omit_session_token=true,
    ),
    expires=3600,
  )
  assert_eq(
    presigned.url,
    "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=e1c9984141670d0cb27cf40af921f76fe885c0ec617fc699dfc92b3da74618d3&X-Amz-Security-Token=session-token",
  )
}

///|
test "sign replaces a caller-supplied Authorization header" {
  let signed = sign(
    {
      meth: @http.Get,
      path: "/",
      query: [],
      headers: [
        ("Host", "example.amazonaws.com"),
        ("Authorization", "stale-old-value"),
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
  let auths = signed.headers.filter(fn(header) {
    header.0.to_lower() == "authorization"
  })
  assert_eq(auths.length(), 1)
  guard! auths[0] is ("Authorization", value)
  assert_true(value.has_prefix("AWS4-HMAC-SHA256 Credential="))
  assert_true(!value.contains("stale-old-value"))
}

///|
test "presign url raises without a Host header" {
  let result = try {
    ignore(
      presign_url(
        request={
          meth: @http.Get,
          path: "/test.txt",
          query: [],
          headers: [],
          body: b"",
        },
        credentials=test_credentials(),
        options=SigningOptions(
          timestamp="20130524T000000Z",
          region="us-east-1",
          service="s3",
          payload_hash=Unsigned,
        ),
        expires=86400,
      ),
    )
    fail("expected presign_url to raise without a Host header")
  } catch {
    Failure(message) => message
    _ => fail("expected a Failure error")
  }
  assert_true(result.contains("Host header"))
}

///|
test "canonical query string sorts and renders wire-form parameters" {
  // parameters arrive exactly as they will appear on the wire: already
  // RFC 3986 component-encoded, duplicates allowed, None for bare keys
  assert_eq(
    canonical_query_string([
      ("X-Amz-Algorithm", Some("AWS4-HMAC-SHA256")),
      ("X-Amz-Credential", Some("a%2Fb")),
      ("X-Amz-Date", Some("t")),
      ("X-Amz-Expires", Some("3600")),
      ("X-Amz-SignedHeaders", Some("host")),
    ]),
    "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=a%2Fb&X-Amz-Date=t&X-Amz-Expires=3600&X-Amz-SignedHeaders=host",
  )
  assert_eq(
    canonical_query_string([
      ("b", Some("2")),
      ("a", Some("1")),
      ("a", Some("0")),
      ("key", None),
    ]),
    "a=0&a=1&b=2&key=",
  )
}
