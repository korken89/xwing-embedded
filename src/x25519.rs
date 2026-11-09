//! The X25519 component.

use derive_more::{AsRef, From, Into};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The X25519 function of RFC 7748 section 5.
///
/// An implementation must not leave a copy of the secret key on the stack, also not a clamped
/// one, and no intermediate value or copy of the result. So it reads the secret by reference,
/// writes the result into a buffer that is wiped on drop, and zeroes the stack it used.
pub trait X25519 {
    /// `X25519(secret, peer)`.
    fn shared_secret(
        &mut self,
        secret: &X25519SecretKey,
        peer: &X25519PublicKey,
    ) -> X25519SharedSecret;

    /// `X25519(secret, 9)`. Override it for a faster fixed-base multiplication.
    fn public_key(&mut self, secret: &X25519SecretKey) -> X25519PublicKey {
        let public = self.shared_secret(secret, &X25519PublicKey::BASE_POINT);
        X25519PublicKey(*public.expose_secret())
    }
}

/// An X25519 scalar, before clamping (RFC 7748 section 5).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X25519SecretKey(pub(crate) [u8; 32]);

impl X25519SecretKey {
    /// Wraps a scalar, for tests of an [`X25519`] implementation.
    pub fn new(scalar: [u8; 32]) -> Self {
        Self(scalar)
    }

    /// The scalar, for an [`X25519`] implementation.
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A public X25519 u-coordinate (RFC 7748 section 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, From, Into, AsRef)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(
    feature = "zerocopy",
    derive(
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::KnownLayout,
        zerocopy::Immutable,
        zerocopy::Unaligned
    )
)]
#[repr(transparent)]
pub struct X25519PublicKey([u8; 32]);

impl X25519PublicKey {
    /// The base point, `u = 9`.
    pub const BASE_POINT: Self = {
        let mut u = [0; 32];
        u[0] = 9;
        Self(u)
    };
}

/// The u-coordinate X25519 computes from a secret and a peer's public key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X25519SharedSecret([u8; 32]);

impl X25519SharedSecret {
    /// Wraps the result of an [`X25519`] implementation.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The secret, for the X-Wing combiner.
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }
}
