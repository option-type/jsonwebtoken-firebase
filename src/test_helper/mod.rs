use std::ops::Add;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use httpmock::MockServer;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rand::thread_rng;

use rsa::pkcs8::ToPrivateKey;
use rsa::{PublicKeyParts, RsaPrivateKey};

use serde::{Deserialize, Serialize};

use crate::Parser;

pub const KID: &str = "some-kid";
pub const CLIENT_ID: &str = "some-client-id";
pub const EMAIL: &str = "hello@example.com";
pub const SUB: &str = "11112222333344445555";

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub email: String,
    pub aud: String,
    pub iss: String,
    pub sub: String,
    pub exp: u64,
}

impl Default for TokenClaims {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenClaims {
    pub fn new() -> Self {
        TokenClaims::new_with_expire(Duration::from_secs(10))
    }

    pub fn new_with_expire(expire: Duration) -> Self {
        Self {
            email: EMAIL.to_owned(),
            aud: CLIENT_ID.to_owned(),
            exp: SystemTime::now()
                .add(expire)
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            iss: "https://example.com".to_owned(),
            sub: SUB.to_owned(),
        }
    }

    pub fn new_expired() -> Self {
        let mut result = TokenClaims::new();
        result.exp = 0;
        result
    }
}

/// A test-only isntantiation of the JWT parser that only has 1 endpoint that
/// it will try to get tokens from
pub(crate) type TestParser = Parser<1>;

pub(crate) fn setup(claims: &TokenClaims) -> (String, TestParser, MockServer) {
    let (token, server) = setup_public_key_server(claims);
    (
        token,
        TestParser::new_with_cert_urls(CLIENT_ID.to_owned(), [server.url("/").as_str()]),
        server,
    )
}

pub fn setup_public_key_server(claims: &TokenClaims) -> (String, MockServer) {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.to_owned());
    header.typ = Some("JWT".to_owned());
    let bits = 2048;
    let private_key =
        RsaPrivateKey::new(&mut thread_rng(), bits).expect("failed to generate a key");
    let der = private_key.to_pkcs8_der().unwrap().to_pem();
    let key = EncodingKey::from_rsa_pem(der.as_bytes()).unwrap();
    let token = jsonwebtoken::encode::<TokenClaims>(&header, claims, &key).unwrap();
    let n = base64::encode_config(private_key.n().to_bytes_be(), base64::URL_SAFE_NO_PAD);
    let e = base64::encode_config(private_key.e().to_bytes_be(), base64::URL_SAFE_NO_PAD);
    let resp = format!("{{\"keys\": [{{\"kty\": \"RSA\",\"use\": \"sig\",\"e\": \"{e}\",\"n\": \"{n}\",\"alg\": \"RS256\",\"kid\": \"{KID}\"}}]}}");

    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/");

        then.status(200)
            .header(
                "cache-control",
                "public, max-age=24920, must-revalidate, no-transform",
            )
            .header("Content-Type", "application/json; charset=UTF-8")
            .body(resp);
    });
    (token, server)
}
