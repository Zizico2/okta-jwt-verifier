#![allow(dead_code)]
pub mod error;
pub mod key;
pub mod token;

use jsonwebtoken::TokenData;
use serde::de::DeserializeOwned;

pub use self::key::{JWK, JWKS};
pub use self::token::DefaultClaims;

pub type Result<T> = std::result::Result<T, error::Error>;

pub async fn verify<T>(issuer: &str, token: &str) -> Result<TokenData<T>>
where
    T: DeserializeOwned,
{
    let kid: String = token::key_id(token)?;
    let keys: JWKS = key::get(issuer).await?;
    let jwk: Option<&JWK> = keys.where_id(&kid);
    match jwk {
        Some(key_jwk) => {
            let key: jsonwebkey::JsonWebKey = serde_json::to_string(&key_jwk)?.parse()?;
            token::decode::<T>(token, key).await
        }
        None => Err(error::Error::Custom("No matching key found!".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[async_std::test]
    async fn can_verify_token() -> Result<()> {
        dotenv::dotenv().ok();
        let issuer = dotenv::var("ISSUER")?;
        let token = dotenv::var("TEST_TOKEN")?;
        verify::<DefaultClaims>(&issuer, &token).await?;
        Ok(())
    }
}
