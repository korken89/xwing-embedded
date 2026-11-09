//! Secret types cannot be copied, compared or logged, and are wiped on drop.

use static_assertions::{assert_impl_all, assert_not_impl_any};
use xwing_embedded::{
    DecapsulationKey, DecapsulationKeySlot, ExpandedKeySlot, MlKem768, MlKemSharedSecret,
    OtfMlKem768, RustCryptoKeySlot, RustCryptoMlKem768, SharedSecret, X25519SecretKey,
    X25519SharedSecret,
};
use zeroize::ZeroizeOnDrop;

macro_rules! secret {
    ($($t:ty),* $(,)?) => {
        $(
            assert_impl_all!($t: ZeroizeOnDrop);
            assert_not_impl_any!($t: Clone, core::fmt::Debug, PartialEq);
            #[cfg(feature = "defmt")]
            assert_not_impl_any!($t: defmt::Format);
        )*
    };
}

secret!(
    DecapsulationKey,
    DecapsulationKeySlot,
    SharedSecret,
    MlKemSharedSecret,
    X25519SecretKey,
    X25519SharedSecret,
    RustCryptoKeySlot,
    ExpandedKeySlot<RustCryptoMlKem768>,
    ExpandedKeySlot<OtfMlKem768>,
    <OtfMlKem768 as MlKem768>::KeySlot,
);

/// An expanded key slot is wiped on drop with any ML-KEM-768.
#[expect(unused, reason = "compile-time check")]
fn expanded_key_slot_is_wiped<M: MlKem768>() {
    fn wiped<T: ZeroizeOnDrop>() {}
    wiped::<ExpandedKeySlot<M>>();
}
