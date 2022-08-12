use std::{
    collections::HashMap,
    sync::atomic::{AtomicBool, Ordering::SeqCst},
    time::Instant,
};

use headers::Header;
use jsonwebtoken::errors::Error;
use jsonwebtoken::DecodingKey;
use reqwest::header::{HeaderMap, CACHE_CONTROL};
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::RwLock as AsyncRwLock;

#[derive(Deserialize, Clone)]
pub struct GoogleKeys {
    keys: Vec<GoogleKey>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct GoogleKey {
    kid: String,
    n: String,
    e: String,
}

#[derive(Error, Debug, Clone)]
pub enum GoogleKeyProviderError {
    #[error("key not found")]
    KeyNotFound,
    #[error("network error {0}")]
    FetchError(String),
    #[error("parse error {0}")]
    ParseError(String),
    #[error("create key error {0}")]
    CreateKeyError(Error),
}

#[derive(Debug)]
pub struct GooglePublicKeyProvider {
    url: String,
    locked_internals: AsyncRwLock<ProviderInternals>,
    reloading: AtomicBool,
}

#[derive(Debug)]
struct ProviderInternals {
    keys: HashMap<String, GoogleKey>,
    expiry: Option<Instant>,
    last_res: Result<(), GoogleKeyProviderError>,
}

impl ProviderInternals {
    async fn refresh_keys(&mut self, url: &str) -> Result<(), GoogleKeyProviderError> {
        use GoogleKeyProviderError::{FetchError, ParseError};
        // just debugs the network error and tosses it into the appropriate keyprovidererror
        fn convert_err<C, D>(f: C) -> impl Fn(D) -> GoogleKeyProviderError
        where
            C: Fn(String) -> GoogleKeyProviderError,
            D: std::fmt::Debug,
        {
            move |e| f(format!("{e:?}"))
        }

        let r = reqwest::get(url).await.map_err(convert_err(FetchError))?;

        let expiration_time = GooglePublicKeyProvider::parse_expiration_time(r.headers());

        let google_keys = r
            .json::<GoogleKeys>()
            .await
            .map_err(convert_err(ParseError))?;

        self.keys.clear();
        self.keys.extend(
            google_keys
                .keys
                .into_iter()
                .map(|key| (key.kid.clone(), key)),
        );
        self.expiry = expiration_time;
        Result::Ok(())
    }
}

impl Default for ProviderInternals {
    fn default() -> Self {
        Self {
            keys: Default::default(),
            expiry: None,
            last_res: Ok(()),
        }
    }
}

impl GooglePublicKeyProvider {
    pub fn new(public_key_url: String) -> Self {
        Self {
            url: public_key_url,
            locked_internals: Default::default(),
            reloading: AtomicBool::new(false),
        }
    }

    pub async fn reload(&self) -> Result<(), GoogleKeyProviderError> {
        // acquire a write lock on the internals. We need to do this because we
        // are expecting this function actually update the internals, and we will only
        // skip the write in the very rare
        if self
            .reloading
            .compare_exchange(false, true, SeqCst, SeqCst)
            .is_ok()
        {
            // we were not reloading, and have now set the reloading flag
            let mut inner = self.locked_internals.write().await;
            let refresh_res = inner.refresh_keys(&self.url).await;
            inner.last_res = refresh_res.clone();
            // we should drop the write handle before we indicate that the reload is complete, or
            // we run a small risk of running this block twice when we don't have to
            drop(inner);
            self.reloading.store(false, SeqCst);
            refresh_res
        } else {
            // we know that when we did the check 7 lines above that we were in the middle of a
            // reload request. Now, we want to wait here until the task that did successfully set
            // obtain the reloading flag is done with its network requests
            let reader = loop {
                // try to grab a reader to the keys. If the above block is currently writing, then
                // this will wait until it's done
                let handle = self.locked_internals.read().await;
                // IMPORTANT: in the event that a different task successfully sets reloading, but
                // we obtain the read lock before it can acquire the write lock, we need to release
                // our handle because the data is stale/expired and the updater needs us to drop
                // our handle before it can proceed
                if !self.reloading.load(SeqCst) {
                    break handle;
                }
                // handle drops here
            };
            reader.last_res.clone()
        }
    }

    fn parse_expiration_time(header_map: &HeaderMap) -> Option<Instant> {
        headers::CacheControl::decode(&mut header_map.get_all(CACHE_CONTROL).iter())
            .ok()
            .and_then(|header| header.max_age().map(|age| Instant::now() + age))
    }

    async fn is_expired(&self) -> bool {
        let read_guard = self.locked_internals.read().await;
        read_guard.expiry.map_or(true, |i| i >= Instant::now())
    }

    pub async fn get_key(&self, kid: &str) -> Result<DecodingKey, GoogleKeyProviderError> {
        if self.is_expired().await {
            self.reload().await?
        }
        let read_guard = self.locked_internals.read().await;
        read_guard
            .keys
            .get(kid)
            .ok_or(GoogleKeyProviderError::KeyNotFound)
            .and_then(|key| {
                DecodingKey::from_rsa_components(key.n.as_str(), key.e.as_str())
                    .map_err(GoogleKeyProviderError::CreateKeyError)
            })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use httpmock::MockServer;

    use crate::keys::{GoogleKeyProviderError, GooglePublicKeyProvider};

    #[tokio::test]
    async fn should_parse_keys() {
        let n = "3g46w4uRYBx8CXFauWh6c5yO4ax_VDu5y8ml_Jd4Gx711155PTdtLeRuwZOhJ6nRy8YvLFPXc_aXtHifnQsi9YuI_vo7LGG2v3CCxh6ndZBjIeFkxErMDg4ELt2DQ0PgJUQUAKCkl2_gkVV9vh3oxahv_BpIgv1kuYlyQQi5JWeF7zAIm0FaZ-LJT27NbsCugcZIDQg9sztTN18L3-P_kYwvAkKY2bGYNU19qLFM1gZkzccFEDZv3LzAz7qbdWkwCoK00TUUH8TNjqmK67bytYzgEgkfF9q9szEQ5TrRL0uFg9LxT3kSTLYqYOVaUIX3uaChwaa-bQvHuNmryu7i9w";
        let e = "AQAB";
        let kid = "some-kid";
        let resp = format!("{{\"keys\": [{{\"kty\": \"RSA\",\"use\": \"sig\",\"e\": \"{}\",\"n\": \"{}\",\"alg\": \"RS256\",\"kid\": \"{}\"}}]}}", e, n, kid);

        let server = MockServer::start();
        let _server_mock = server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/");

            then.status(200)
                .header(
                    "cache-control",
                    "public, max-age=24920, must-revalidate, no-transform",
                )
                .header("Content-Type", "application/json; charset=UTF-8")
                .body(resp);
        });
        let provider = GooglePublicKeyProvider::new(server.url("/"));

        assert!(matches!(provider.get_key(kid).await, Result::Ok(_)));
        assert!(matches!(
            provider.get_key("missing-key").await,
            Result::Err(_)
        ));
    }

    #[tokio::test]
    async fn should_expire_and_reload() {
        let server = MockServer::start();
        let n = "3g46w4uRYBx8CXFauWh6c5yO4ax_VDu5y8ml_Jd4Gx711155PTdtLeRuwZOhJ6nRy8YvLFPXc_aXtHifnQsi9YuI_vo7LGG2v3CCxh6ndZBjIeFkxErMDg4ELt2DQ0PgJUQUAKCkl2_gkVV9vh3oxahv_BpIgv1kuYlyQQi5JWeF7zAIm0FaZ-LJT27NbsCugcZIDQg9sztTN18L3-P_kYwvAkKY2bGYNU19qLFM1gZkzccFEDZv3LzAz7qbdWkwCoK00TUUH8TNjqmK67bytYzgEgkfF9q9szEQ5TrRL0uFg9LxT3kSTLYqYOVaUIX3uaChwaa-bQvHuNmryu7i9w";
        let e = "AQAB";
        let kid = "some-kid";
        let resp = format!("{{\"keys\": [{{\"kty\": \"RSA\",\"use\": \"sig\",\"e\": \"{}\",\"n\": \"{}\",\"alg\": \"RS256\",\"kid\": \"{}\"}}]}}", e, n, kid);

        let mut server_mock = server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/");
            then.status(200)
                .header(
                    "cache-control",
                    "public, max-age=3, must-revalidate, no-transform",
                )
                .header("Content-Type", "application/json; charset=UTF-8")
                .body("{\"keys\":[]}");
        });

        let provider = GooglePublicKeyProvider::new(server.url("/"));
        let key_result = provider.get_key(kid).await;
        assert!(matches!(
            key_result,
            Result::Err(GoogleKeyProviderError::KeyNotFound)
        ));

        server_mock.delete();
        let _server_mock = server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/");
            then.status(200)
                .header(
                    "cache-control",
                    "public, max-age=3, must-revalidate, no-transform",
                )
                .header("Content-Type", "application/json; charset=UTF-8")
                .body(resp);
        });

        std::thread::sleep(Duration::from_secs(4));
        let key_result = provider.get_key(kid).await;
        assert!(matches!(key_result, Result::Ok(_)));
    }
}
