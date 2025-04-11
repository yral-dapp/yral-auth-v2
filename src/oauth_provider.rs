use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
    time::Duration,
};

use enum_dispatch::enum_dispatch;
use openidconnect::ClientSecret;
use serde::{Deserialize, Serialize};

use crate::utils::time::current_epoch;

pub type StdOAuthClient = openidconnect::Client<
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

#[enum_dispatch]
pub(crate) trait OAuthProvider {
    fn get_client(&self) -> Arc<StdOAuthClient>;
}

pub struct IdentityOAuthProvider(Arc<StdOAuthClient>);

impl IdentityOAuthProvider {
    pub fn new(client_secret: StdOAuthClient) -> Self {
        Self(Arc::new(client_secret))
    }
}

impl OAuthProvider for IdentityOAuthProvider {
    fn get_client(&self) -> Arc<StdOAuthClient> {
        self.0.clone()
    }
}

// we need a custom implementation for apple because
// client secrets for apple login are only valid for 6 months
// the implementation automatically refreshes the client secret
// when it expires
pub struct AppleOAuthProvider {
    keygen: AppleClientSecretGen,
    // extremely unholy
    cache: RwLock<Arc<StdOAuthClient>>,
    cache_expiry_epoch_secs: AtomicU64,
}

#[derive(Serialize, Deserialize)]
struct AppleSecretClaims {
    iss: String,
    iat: u64,
    exp: u64,
    aud: String,
    sub: String,
}

struct AppleClientSecretGen {
    auth_key: jsonwebtoken::EncodingKey,
    key_id: String,
    team_id: String,
    client_id: String,
}

impl AppleClientSecretGen {
    fn new(
        auth_key: jsonwebtoken::EncodingKey,
        key_id: String,
        team_id: String,
        client_id: String,
    ) -> Self {
        Self {
            auth_key,
            key_id,
            team_id,
            client_id,
        }
    }

    fn generate_client_secret(&self) -> (ClientSecret, u64) {
        let iat = current_epoch();
        // slightly less than 6 months to be safe
        let exp = iat + Duration::from_secs(14777000);
        let claims = AppleSecretClaims {
            iss: self.team_id.clone(),
            iat: iat.as_secs(),
            exp: exp.as_secs(),
            aud: "https://appleid.apple.com".to_string(),
            sub: self.client_id.clone(),
        };
        let mut token_header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        token_header.kid = Some(self.key_id.clone());

        let token = jsonwebtoken::encode(&token_header, &claims, &self.auth_key)
            .expect("Failed to encode Apple client secret?!");

        let client_secret = ClientSecret::new(token);
        // slightly less than **actual** token expiry to be safe
        let stored_expiry = exp - Duration::from_secs(60 * 60);

        (client_secret, stored_expiry.as_secs())
    }
}

impl AppleOAuthProvider {
    pub fn new(
        base_client: StdOAuthClient,
        auth_key: jsonwebtoken::EncodingKey,
        key_id: String,
        team_id: String,
    ) -> Self {
        let keygen = AppleClientSecretGen::new(
            auth_key,
            key_id,
            team_id,
            base_client.client_id().to_string(),
        );
        let (client_secret, expiry_epoch) = keygen.generate_client_secret();
        let client = base_client.set_client_secret(client_secret);
        let cache = RwLock::new(Arc::new(client));
        let cache_expiry_epoch_secs = AtomicU64::new(expiry_epoch);

        Self {
            keygen,
            cache,
            cache_expiry_epoch_secs,
        }
    }
}

impl OAuthProvider for AppleOAuthProvider {
    fn get_client(&self) -> Arc<StdOAuthClient> {
        let cur_epoch = current_epoch().as_secs();
        let cur_exp = self.cache_expiry_epoch_secs.load(Ordering::Acquire);
        if cur_epoch < cur_exp {
            return self.cache.read().unwrap().clone();
        }

        let mut cache = self.cache.write().unwrap();
        let (client_secret, expiry_epoch) = self.keygen.generate_client_secret();

        let new_client = cache
            .as_ref()
            .clone()
            .set_client_secret(client_secret.clone());
        let new_client = Arc::new(new_client);
        *cache = new_client.clone();
        self.cache_expiry_epoch_secs
            .store(expiry_epoch, Ordering::Release);

        new_client
    }
}

#[enum_dispatch(OAuthProvider)]
pub enum OAuthProviderImpl {
    IdentityOAuthProvider,
    AppleOAuthProvider,
}
