use std::collections::{HashMap, HashSet};

use anyhow::{bail, Result};
use jsonwebkey::JsonWebKey;
use jsonwebtoken::{TokenData, Validation};
use serde::{de::DeserializeOwned, Deserialize, Serialize};


/// Describes the default claims inside a decoded token
#[derive(Debug, Serialize, Deserialize)]
pub struct DefaultClaims {
    /// The Issuer Identifier of the response.
    /// This value is the unique identifier for the Authorization Server instance.
    pub iss: String,
    /// The subject of the token.
    pub sub: String,
    /// Array of scopes that are granted to this access token.
    pub scp: Option<Vec<String>>,
    /// Client ID of the client that requested the access token.
    pub cid: Option<String>,
    /// A unique identifier for the user.
    /// It isn't included in the access token if there is no user bound to it.
    pub uid: Option<String>,
    /// The time the access token expires, represented in Unix time (seconds).
    pub exp: u64,
    /// The time the access token was issued, represented in Unix time (seconds).
    pub iat: u64,
}

// Describes the key retrieved from upstream
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Jwk {
    // The "kty" (key type) parameter identifies the cryptographic algorithm
    // family used with the key, such as "RSA" or "EC".
    kty: String,
    // The "alg" (algorithm) parameter identifies the algorithm intended for
    // use with the key.
    alg: String,
    // The "kid" (key ID) parameter is used to match a specific key.  This
    // is used, for instance, to choose among a set of keys within a Jwk Set
    // during key rollover.  The structure of the "kid" value is
    // unspecified.  When "kid" values are used within a Jwk Set, different
    // keys within the Jwk Set SHOULD use distinct "kid" values.
    kid: String,
    // The "use" (public key use) parameter identifies the intended use of
    // the public key.  The "use" parameter is employed to indicate whether
    // a public key is used for encrypting data or verifying the signature
    // on data.
    #[serde(rename = "use")]
    uses: String,
    // RSA public exponent is used on signed / encoded data to decode the original value
    e: String,
    // RSA modulus is the product of two prime numbers used to generate the key pair
    n: String,
}

// Container for keys
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Jwks {
    inner: HashMap<String, Jwk>,
}

// Describes issuer keys response
#[derive(Debug, Deserialize)]
struct KeyResponse {
    keys: Vec<Jwk>,
}

// Needed for the cid verification workaround
#[derive(Debug, Serialize, Deserialize)]
struct ClientId {
    cid: String,
}

impl Jwks {
    // Attempts to retrieve a key by given id
    pub fn where_id(&self, kid: &str) -> Option<&Jwk> {
        self.inner.get(kid)
    }
}


fn build_client() -> reqwest::Client {
    reqwest::Client::new()
}

/// Attempts to retrieve the keys from an Okta issuer,
/// decode and verify a given access/ID token, and
/// deserialize the requested claims.
#[derive(Debug, Clone)]
pub struct Verifier {
    issuer: String,
    cid: Option<String>,
    leeway: Option<u64>,
    aud: Option<HashSet<String>>,
    keys: Jwks,
}

impl Verifier {
    /// `new` constructs an instance of Verifier and attempts
    /// to retrieve the keys from the specified issuer.
    pub async fn new(issuer: &str) -> Result<Self> {
        let keys = get(issuer).await?;
        Ok(Self {
            issuer: issuer.to_string(),
            cid: None,
            leeway: None,
            aud: None,
            keys,
        })
    }

    /// `verify` will attempt to validate a passed access
    /// or ID token. Upon a successful validation it will then
    /// attempt to deserialize the requested claims. A [`DefaultClaims`]
    /// struct has been provided for use or to serve as an example
    /// for constructing a custom claim struct.
    ///
    /// ```no_run
    /// use okta_jwt_verifier::{Verifier, DefaultClaims};
    ///
    /// #[async_std::main]
    /// async fn main() -> anyhow::Result<()> {
    ///     let token = "token";
    ///     let issuer = "https://your.domain/oauth2/default";
    ///
    ///     Verifier::new(&issuer)
    ///         .await?
    ///         .verify::<DefaultClaims>(&token)
    ///         .await?;
    ///     Ok(())
    /// }
    ///```
    pub async fn verify<T>(&self, token: &str) -> Result<TokenData<T>>
    where
        T: DeserializeOwned,
    {
        let kid: String = self.key_id(token)?;
        let jwk: Option<&Jwk> = self.keys.where_id(&kid);
        match jwk {
            Some(key_jwk) => self.decode::<T>(token, key_jwk).await,
            None => bail!("No matching key found!"),
        }
    }

    /// `client_id` can be used to require cid claim verification.
    ///
    /// ```no_run
    /// use okta_jwt_verifier::{Verifier, DefaultClaims};
    ///
    /// #[async_std::main]
    /// async fn main() -> anyhow::Result<()> {
    ///     let token = "token";
    ///     let issuer = "https://your.domain/oauth2/default";
    ///
    ///     Verifier::new(&issuer)
    ///         .await?
    ///         .client_id("Bl3hStrINgiD")
    ///         .verify::<DefaultClaims>(&token)
    ///         .await?;
    ///     Ok(())
    /// }
    ///```
    pub fn client_id(mut self, cid: &str) -> Self {
        self.cid = Some(cid.to_string());
        self
    }

    /// `audience` is for setting multiple aud values
    /// to check against.
    ///
    /// ```no_run
    /// use okta_jwt_verifier::{Verifier, DefaultClaims};
    /// use std::collections::HashSet;
    ///
    /// #[async_std::main]
    /// async fn main() -> anyhow::Result<()> {
    ///     let token = "token";
    ///     let issuer = "https://your.domain/oauth2/default";
    ///     let mut aud = HashSet::new();
    ///     aud.insert("api://default".to_string());
    ///     aud.insert("api://admin".to_string());
    ///
    ///     Verifier::new(&issuer)
    ///         .await?
    ///         .audience(aud)
    ///         .verify::<DefaultClaims>(&token)
    ///         .await?;
    ///     Ok(())
    /// }
    ///```
    pub fn audience(mut self, audience: HashSet<String>) -> Self {
        self.aud = Some(audience);
        self
    }

    /// `add_audience` helps to make adding a single
    /// aud entry easier.
    ///
    /// ```no_run
    /// use okta_jwt_verifier::{Verifier, DefaultClaims};
    ///
    /// #[async_std::main]
    /// async fn main() -> anyhow::Result<()> {
    ///     let token = "token";
    ///     let issuer = "https://your.domain/oauth2/default";
    ///
    ///     Verifier::new(&issuer)
    ///         .await?
    ///         .add_audience("api://default")
    ///         .verify::<DefaultClaims>(&token)
    ///         .await?;
    ///     Ok(())
    /// }
    ///```
    pub fn add_audience(mut self, audience: &str) -> Self {
        if let Some(mut a) = self.aud.clone() {
            a.insert(audience.to_string());
        } else {
            let mut a = HashSet::new();
            a.insert(audience.to_string());
            self.aud = Some(a);
        }
        self
    }

    /// `leeway` is for overriding the default leeway
    /// of 120 seconds, this is to help deal with clock skew.
    ///
    /// ```no_run
    /// use okta_jwt_verifier::{Verifier, DefaultClaims};
    ///
    /// #[async_std::main]
    /// async fn main() -> anyhow::Result<()> {
    ///     let token = "token";
    ///     let issuer = "https://your.domain/oauth2/default";
    ///
    ///     Verifier::new(&issuer)
    ///         .await?
    ///         .leeway(60)
    ///         .verify::<DefaultClaims>(&token)
    ///         .await?;
    ///     Ok(())
    /// }
    ///```
    pub fn leeway(mut self, leeway: u64) -> Self {
        self.leeway = Some(leeway);
        self
    }

    // Attempts to retrieve a key id for a given token
    fn key_id(&self, token: &str) -> Result<String> {
        let header = jsonwebtoken::decode_header(token)?;
        if header.kid.is_some() {
            Ok(header.kid.unwrap())
        } else {
            bail!("No key id found!")
        }
    }

    // Attempts to decode the passed token and deserialize the claims
    async fn decode<T>(
        &self,
        token: &str,
        key_jwk: &Jwk,
    ) -> Result<TokenData<T>>
    where
        T: DeserializeOwned,
    {
        let key: JsonWebKey = serde_json::to_string(key_jwk)?.parse()?;
        let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
        if let Some(cid) = &self.cid {
            // This isn't ideal but what we have to do for now
            let cid_tdata = jsonwebtoken::decode::<ClientId>(
                token,
                &key.key.to_decoding_key(),
                &validation,
            )?;
            if &cid_tdata.claims.cid != cid {
                bail!("client_id validation failed!")
            }
        }
        if let Some(secs) = self.leeway {
            validation.leeway = secs;
        } else {
            // default PT2M
            validation.leeway = 120;
        }
        validation.aud = self.aud.clone();
        let mut iss = HashSet::new();
        iss.insert(self.issuer.clone());
        validation.iss = Some(iss);
        let tdata = jsonwebtoken::decode::<T>(
            token,
            &key.key.to_decoding_key(),
            &validation,
        )?;
        Ok(tdata)
    }
}

// Attempts to retrieve the keys from the issuer
async fn get(issuer: &str) -> Result<Jwks> {
    let url = format!("{}/v1/keys", &issuer);
    let req = reqwest::get(&url);
    let res = match req.await {
        Ok(r) => r,
        Err(e) => {
            bail!(e)
        }
    };
    let KeyResponse { keys } = match res.json().await {
        Ok(k) => k,
        Err(e) => {
            bail!(e)
        }
    };
    let mut keymap = Jwks { inner: HashMap::new() };
    for key in keys {
        keymap.inner.insert(key.kid.clone(), key);
    }
    Ok(keymap)
}
