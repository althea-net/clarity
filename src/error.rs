/// Custom error implementation that describes possible
/// error states.
///
/// This is shared by a whole crate.
#[derive(Fail, Debug)]
pub enum ClarityError {
    #[fail(display = "Invalid network id")]
    InvalidNetworkId,
    #[fail(display = "Invalid V value")]
    InvalidV,
    #[fail(display = "Invalid S value")]
    InvalidS,
    #[fail(display = "Invalid signature values")]
    InvalidSignatureValues,
    #[fail(display = "Zero priv key cannot sign")]
    ZeroPrivKey,
    #[fail(display = "Invalid private key")]
    InvalidPrivKey,
}
