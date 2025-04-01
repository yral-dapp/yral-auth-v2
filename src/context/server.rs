use std::{collections::HashMap, env, sync::Arc};

use axum::extract::FromRef;
use leptos::{config::LeptosOptions, prelude::expect_context};
use leptos_axum::AxumRouteListing;
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata},
    reqwest, ClientId, ClientSecret, IssuerUrl, RedirectUrl,
};

use crate::{
    consts::GOOGLE_ISSUER_URL,
    kv::KVStoreImpl,
    oauth::{client_validation::ClientIdValidatorImpl, SupportedOAuthProviders},
};

type OAuthProvider = openidconnect::Client<
    openidconnect::EmptyAdditionalClaims,
    openidconnect::core::CoreAuthDisplay,
    openidconnect::core::CoreGenderClaim,
    openidconnect::core::CoreJweContentEncryptionAlgorithm,
    openidconnect::core::CoreJsonWebKey,
    openidconnect::core::CoreAuthPrompt,
    openidconnect::StandardErrorResponse<openidconnect::core::CoreErrorResponseType>,
    openidconnect::StandardTokenResponse<
        openidconnect::IdTokenFields<
            openidconnect::EmptyAdditionalClaims,
            openidconnect::EmptyExtraTokenFields,
            openidconnect::core::CoreGenderClaim,
            openidconnect::core::CoreJweContentEncryptionAlgorithm,
            openidconnect::core::CoreJwsSigningAlgorithm,
        >,
        openidconnect::core::CoreTokenType,
    >,
    openidconnect::StandardTokenIntrospectionResponse<
        openidconnect::EmptyExtraTokenFields,
        openidconnect::core::CoreTokenType,
    >,
    openidconnect::core::CoreRevocableToken,
    openidconnect::StandardErrorResponse<openidconnect::RevocationErrorResponseType>,
    openidconnect::EndpointSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointMaybeSet,
    openidconnect::EndpointMaybeSet,
>;

#[derive(FromRef, Clone)]
pub struct ServerState {
    pub leptos_options: LeptosOptions,
    pub routes: Vec<AxumRouteListing>,
    pub ctx: Arc<ServerCtx>,
}

pub struct JwkPair {
    pub encoding_key: jsonwebtoken::EncodingKey,
    pub decoding_key: jsonwebtoken::DecodingKey,
}

impl JwkPair {
    pub fn load_from_env(encoding_env: &str, decoding_env: &str) -> Self {
        let jwt_pem =
            env::var(encoding_env).unwrap_or_else(|_| panic!("`{encoding_env}` is required!"));
        let jwt_pub_pem =
            env::var(decoding_env).unwrap_or_else(|_| panic!("`{decoding_env}` is required!"));

        let encoding_key = jsonwebtoken::EncodingKey::from_ed_pem(jwt_pem.as_bytes())
            .unwrap_or_else(|_| panic!("invalid `{encoding_env}`"));
        let decoding_key = jsonwebtoken::DecodingKey::from_ed_pem(jwt_pub_pem.as_bytes())
            .unwrap_or_else(|_| panic!("invalid `{decoding_env}`"));

        Self {
            encoding_key,
            decoding_key,
        }
    }
}

pub struct JwkPairs {
    pub auth_tokens: JwkPair,
    pub client_tokens: JwkPair,
}

impl Default for JwkPairs {
    fn default() -> Self {
        Self {
            auth_tokens: JwkPair::load_from_env("JWT_ED_PEM", "JWT_PUB_ED_PEM"),
            client_tokens: JwkPair::load_from_env("CLIENT_JWT_ED_PEM", "CLIENT_JWT_PUB_ED_PEM"),
        }
    }
}

pub struct ServerCtx {
    pub oauth_http_client: reqwest::Client,
    pub oauth_providers: HashMap<SupportedOAuthProviders, OAuthProvider>,
    pub cookie_key: axum_extra::extract::cookie::Key,
    pub jwk_pairs: JwkPairs,
    pub kv_store: KVStoreImpl,
    pub validator: ClientIdValidatorImpl,
}

impl ServerCtx {
    async fn init_oauth_providers(
        http_client: &reqwest::Client,
    ) -> HashMap<SupportedOAuthProviders, OAuthProvider> {
        let mut oauth_providers = HashMap::new();

        let client_id = env::var("GOOGLE_CLIENT_ID").expect("`GOOGLE_CLIENT_ID` is required!");
        let client_secret =
            env::var("GOOGLE_CLIENT_SECRET").expect("`GOOGLE_CLIENT_SECRET` is required!");
        let redirect_uri =
            env::var("GOOGLE_REDIRECT_URL").expect("`GOOGLE_REDIRECT_URI` is required!");

        let google_oauth_metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(GOOGLE_ISSUER_URL.to_string()).unwrap(),
            http_client,
        )
        .await
        .unwrap();

        let google_oauth = CoreClient::from_provider_metadata(
            google_oauth_metadata,
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_uri).unwrap());

        oauth_providers.insert(SupportedOAuthProviders::Google, google_oauth);

        oauth_providers
    }

    fn init_cookie_key() -> axum_extra::extract::cookie::Key {
        let cookie_key_str = env::var("COOKIE_KEY").expect("`COOKIE_KEY` is required!");
        let cookie_key_raw =
            hex::decode(cookie_key_str).expect("Invalid `COOKIE_KEY` (must be length 128 hex)");
        axum_extra::extract::cookie::Key::from(&cookie_key_raw)
    }

    pub async fn init_kv_store() -> KVStoreImpl {
        #[cfg(not(feature = "redis-kv"))]
        {
            use crate::kv::redb_kv::ReDBKV;
            KVStoreImpl::ReDB(ReDBKV::new().unwrap())
        }
        #[cfg(feature = "redis-kv")]
        {
            use crate::kv::redis_kv::RedisKV;
            let redis_url = env::var("REDIS_URL").expect("`REDIS_URL` is required!");
            KVStoreImpl::Redis(
                RedisKV::new(&redis_url)
                    .await
                    .expect("Failed to initialize RedisKV"),
            )
        }
    }

    pub async fn new() -> Self {
        let oauth_http_client = reqwest::ClientBuilder::new()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Client should build");
        let oauth_providers = Self::init_oauth_providers(&oauth_http_client).await;

        let cookie_key = Self::init_cookie_key();

        let kv_store = Self::init_kv_store().await;

        Self {
            oauth_http_client,
            oauth_providers,
            cookie_key,
            jwk_pairs: JwkPairs::default(),
            kv_store,
            validator: ClientIdValidatorImpl::Const(Default::default()),
        }
    }
}

pub fn expect_server_ctx() -> Arc<ServerCtx> {
    expect_context()
}
