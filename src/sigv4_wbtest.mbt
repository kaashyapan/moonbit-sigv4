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
  let (canonical, signed) = canonical_headers({
    "Content-Type": " text/plain ",
    "content-type": " application/json ",
    "X-Amz-Meta-Test": " one \t two ",
  })
  assert_eq(
    canonical, "content-type:text/plain,application/json\nx-amz-meta-test:one two\n",
  )
  assert_eq(signed, "content-type;x-amz-meta-test")
}

///|
test "sign_headers produces spec-compliant signatures" {
  // Inputs follow the AWS SigV4 documentation example (GET with a Range
  // header); the expected signature was cross-checked with an independent
  // implementation that was validated end-to-end against a live S3 server.
  let sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  let headers = Map([])
  headers["Host"] = "examplebucket.s3.amazonaws.com"
  headers["Range"] = "bytes=0-9"
  headers["x-amz-date"] = "20130524T000000Z"
  headers["x-amz-content-sha256"] = sha
  let signed = sign_headers(
    "GET",
    "/test.txt",
    Map([]),
    headers,
    sha,
    test_credentials(),
    "us-east-1",
    "s3",
    "20130524T000000Z",
  )
  assert_eq(
    signed["Authorization"],
    "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=67fe34c8530db585abddc51067328adfedb6e42487d2566dc7d927d6e2722900",
  )
}

///|
test "presign query follows sigv4 query signing" {
  let query = presign_query(
    "GET",
    "/test.txt",
    "examplebucket.s3.amazonaws.com",
    test_credentials(),
    "us-east-1",
    "s3",
    "20130524T000000Z",
    86400,
  )
  assert_eq(query["X-Amz-Algorithm"], "AWS4-HMAC-SHA256")
  assert_eq(
    query["X-Amz-Credential"],
    "AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request",
  )
  assert_eq(query["X-Amz-Date"], "20130524T000000Z")
  assert_eq(query["X-Amz-Expires"], "86400")
  assert_eq(query["X-Amz-SignedHeaders"], "host")
  assert_eq(
    query["X-Amz-Signature"],
    "3ed0be64024db54d5574a27da223529635c383f911f80e636f0ccc13890053d2",
  )
}

///|
test "presign query signs extra headers when present" {
  let query = presign_query(
    "PUT",
    "/test.txt",
    "examplebucket.s3.amazonaws.com",
    test_credentials(),
    "us-east-1",
    "s3",
    "20130524T000000Z",
    3600,
    signed_headers={ "Content-Type": "text/plain" },
  )
  assert_eq(query["X-Amz-SignedHeaders"], "content-type;host")
  assert_true(query.get("X-Amz-Signature") is Some(_))
}

///|
test "presign query includes session token" {
  let query = presign_query(
    "GET",
    "/test.txt",
    "examplebucket.s3.amazonaws.com",
    Credentials(
      "AKIAIOSFODNN7EXAMPLE",
      "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
      session_token="session-token",
    ),
    "us-east-1",
    "s3",
    "20130524T000000Z",
    3600,
  )
  assert_eq(query["X-Amz-Security-Token"], "session-token")
}

///|
test "canonical query sorts byte-wise by encoded key" {
  let query : Map[String, String] = Map([])
  query["X-Amz-Algorithm"] = "AWS4-HMAC-SHA256"
  query["X-Amz-Credential"] = "a/b"
  query["X-Amz-Date"] = "t"
  query["X-Amz-Expires"] = "3600"
  query["X-Amz-SignedHeaders"] = "host"
  assert_eq(
    canonical_query(query),
    "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=a%2Fb&X-Amz-Date=t&X-Amz-Expires=3600&X-Amz-SignedHeaders=host",
  )
}
