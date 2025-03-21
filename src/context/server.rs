use std::{collections::HashMap, env, sync::Arc};

use axum::extract::FromRef;
use leptos::{config::LeptosOptions, prelude::expect_context};
use leptos_axum::AxumRouteListing;
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata},
    reqwest, ClientId, ClientSecret, IssuerUrl, RedirectUrl,
};

use crate::{consts::GOOGLE_ISSUER_URL, kv::KVStoreImpl, oauth::SupportedOAuthProviders};

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

pub struct ServerCtx {
    pub oauth_http_client: reqwest::Client,
    pub oauth_providers: HashMap<SupportedOAuthProviders, OAuthProvider>,
    pub cookie_key: axum_extra::extract::cookie::Key,
    pub jwt_encoding_key: jsonwebtoken::EncodingKey,
    pub jwt_decoding_key: jsonwebtoken::DecodingKey,
    pub kv_store: KVStoreImpl,
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

    pub fn init_jwt_keys() -> (jsonwebtoken::EncodingKey, jsonwebtoken::DecodingKey) {
        let jwt_pem = env::var("JWT_ED_PEM").expect("`JWT_ED_PEM` is required!");
        let jwt_pub_pem = env::var("JWT_PUB_ED_PEM").expect("`JWT_PUB_ED_PEM` is required!");
        let jwt_encoding_key = jsonwebtoken::EncodingKey::from_ed_pem(jwt_pem.as_bytes())
            .expect("invalid `JWT_ED_PEM`");
        let jwt_decoding_key = jsonwebtoken::DecodingKey::from_ed_pem(jwt_pub_pem.as_bytes())
            .expect("invalid `JWT_PUB_ED_PEM`");
        (jwt_encoding_key, jwt_decoding_key)
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

        let (jwt_encoding_key, jwt_decoding_key) = Self::init_jwt_keys();

        let kv_store = Self::init_kv_store().await;

        Self {
            oauth_http_client,
            oauth_providers,
            cookie_key,
            jwt_encoding_key,
            jwt_decoding_key,
            kv_store,
        }
    }
}

pub fn expect_server_ctx() -> Arc<ServerCtx> {
    expect_context()
}
