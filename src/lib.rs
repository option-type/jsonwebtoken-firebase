use futures::{future::try_join_all, Future};
use jsonwebtoken::{Algorithm, Validation};
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::keys::{GoogleKeyProviderError, GooglePublicKeyProvider};
use std::convert::TryInto;

mod keys;

#[cfg(any(test, feature = "test-helper"))]
pub mod test_helper;

///
/// Parser errors
///
#[derive(Error, Debug)]
pub enum ParserError {
    #[error("Wrong header.")]
    WrongHeader,
    #[error("Unknown kid.")]
    UnknownKid,
    #[error("Download public key error - {0}.")]
    KeyProvider(GoogleKeyProviderError),
    #[error("Wrong token format - {0}.")]
    WrongToken(jsonwebtoken::errors::Error),
}

pub struct GCP;

impl GCP {
    pub const TOKEN_URL: &'static str = "https://www.googleapis.com/oauth2/v3/certs";
}

pub struct Firebase;

impl Firebase {
    pub const TOKEN_URL: &'static str =
        "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";
}

///
/// Parse & Validate Google JWT token.
/// Use public key from http(s) server.
///
pub struct Parser<const N: usize> {
    client_id: String,
    key_providers: [GooglePublicKeyProvider; N],
}

impl Parser<1> {
    pub fn new_gcp(client_id: String) -> Self {
        Self::new_with_cert_urls(client_id, [GCP::TOKEN_URL])
    }
    pub fn new_firebase(client_id: String) -> Self {
        Self::new_with_cert_urls(client_id, [Firebase::TOKEN_URL])
    }
}

impl Parser<2> {
    pub fn new(client_id: String) -> Self {
        Self::new_with_cert_urls(client_id, [GCP::TOKEN_URL, Firebase::TOKEN_URL])
    }
}

impl<const N: usize> Parser<N> {
    pub fn new_with_cert_urls(client_id: String, public_key_urls: [&str; N]) -> Self {
        let key_providers: [GooglePublicKeyProvider; N] = public_key_urls
            .into_iter()
            .map(String::from)
            .map(GooglePublicKeyProvider::new)
            // unfortunately, there's no way to avoid collecting into
            // a heap-allocated structure before converting into an
            // array of known size on the stack
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        Self {
            client_id,
            key_providers,
        }
    }

    ///
    /// Parse and validate token.
    /// Download and cache public keys from http(s) server.
    /// Use expire time header for reload keys.
    pub async fn parse<T: DeserializeOwned>(
        &self,
        token: &str,
        issuers: &[String],
    ) -> Result<T, ParserError> {
        let header = jsonwebtoken::decode_header(token).map_err(|_| ParserError::WrongHeader)?;
        let kid = header.kid.ok_or(ParserError::UnknownKid)?;
        let kid = kid.as_str();
        let get_key_tasks = self.key_providers.iter().map(|provider| async move {
            // raw_res is how we would originally would get the key from a singular
            // provider. However, since we may have multiple providers, we have
            // to do this get_key on every provider to see if any of them contain the
            // auth for us
            let key = provider
                .get_key(kid)
                .await
                .map_err(ParserError::KeyProvider)?;

            let aud = vec![self.client_id.to_owned()];
            let validation = {
                let mut v = Validation::new(Algorithm::RS256);
                v.set_audience(&aud);
                v.set_issuer(issuers);
                v.validate_exp = true;
                v.validate_nbf = false;
                v
            };
            jsonwebtoken::decode::<T>(token, &key, &validation)
                .map(|token_data| token_data.claims)
                .map_err(ParserError::WrongToken)
        });
        get_first_success(get_key_tasks).await
    }
}

/// Given an iterator over Futures that can return a result, this function will "race" these futures and return the
/// output of the future that first came back with an `Ok`. This is useful when you need a valid response from any one
/// of multiple (async) sources with varying latency.
///
/// For example, imagine we have 3 redundant servers, (A, B, and C) that do some compute for us, which we interface with
/// like so:
/// ```no_run
///
/// use jsonwebtoken_firebase::get_first_success;
/// use tokio::time::sleep;
/// use std::time::Duration;
///
/// let futs = ['A', 'B', 'C'].into_iter().map(|c| async move {
///      let n = c as u64;
///      sleep(Duration::from_millis(n)).await;
///      Ok(n)
/// });
/// async {
///     // we would expect this to be the char value of A, since that future would complete first
///     let reply: Result<u64, String> = get_first_success(futs).await;
/// };
/// ```
/// Given a "reply order" like so
///
/// | Service | Time MS | response                    |
/// |---------|---------|-----------------------------|
/// | B       | 50ms    | Ok(42)                      |
/// | C       | 25ms    | Err("oops")                 |
/// | A       | >50ms   | Unknown (request cancelled) |
///
/// This function will return the Ok(42) from B after 50ms and ignore the error from C. `Result::Err` will be returned
/// iff every request fails. Note that in the above example, the reply from service A is unknown because we drop its
/// task as soon as B returns the Ok to us. The following reply order will give `Err("IDK")`
///
/// | Service | Time MS | response     |
/// |---------|---------|--------------|
/// | B       | 50ms    | Err("uh oh") |
/// | C       | 25ms    | Err("oops")  |
/// | A       | 100ms   | Err("IDK")   |
pub async fn get_first_success<I, T, E>(i: I) -> Result<T, E>
where
    I: IntoIterator,
    <I as IntoIterator>::Item: Future<Output = Result<T, E>>,
{
    fn invert_result<T, E>(r: Result<T, E>) -> Result<E, T> {
        match r {
            Ok(v) => Err(v),
            Err(v) => Ok(v),
        }
    }
    let x = try_join_all(i.into_iter().map(|fut| async {
        let r = fut.await;
        invert_result(r)
    }))
    .await
    .map(|mut errors| errors.pop().unwrap());
    invert_result(x)
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::errors::ErrorKind;

    use crate::test_helper::{setup, TokenClaims};
    use crate::ParserError;

    #[tokio::test]
    async fn should_correct() {
        let claims = TokenClaims::new();
        let (token, parser, _server) = setup(&claims);
        let result = parser
            .parse::<TokenClaims>(token.as_str(), &["https://example.com".to_string()])
            .await;
        let result = result.unwrap();
        assert_eq!(result.email, claims.email);
    }

    #[tokio::test]
    async fn should_validate_exp() {
        let claims = TokenClaims::new_expired();
        let (token, validator, _server) = setup(&claims);
        let result = validator
            .parse::<TokenClaims>(token.as_str(), &["https://example.com".to_string()])
            .await;

        assert!(
            if let ParserError::WrongToken(error) = result.err().unwrap() {
                matches!(error.into_kind(), ErrorKind::ExpiredSignature)
            } else {
                false
            }
        );
    }

    #[tokio::test]
    async fn should_validate_iss() {
        let mut claims = TokenClaims::new();
        claims.iss = "https://some.com".to_owned();
        let (token, validator, _server) = setup(&claims);
        let result = validator
            .parse::<TokenClaims>(token.as_str(), &["https://example.com".to_string()])
            .await;
        assert!(
            if let ParserError::WrongToken(error) = result.err().unwrap() {
                matches!(error.into_kind(), ErrorKind::InvalidIssuer)
            } else {
                false
            }
        );
    }

    #[tokio::test]
    async fn should_validate_aud() {
        let mut claims = TokenClaims::new();
        claims.aud = "other-id".to_owned();
        let (token, validator, _server) = setup(&claims);
        let result = validator
            .parse::<TokenClaims>(token.as_str(), &["https://example.com".to_string()])
            .await;
        assert!(
            if let ParserError::WrongToken(error) = result.err().unwrap() {
                matches!(error.into_kind(), ErrorKind::InvalidAudience)
            } else {
                false
            }
        );
    }
}
