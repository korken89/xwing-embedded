//! Known answer tests through the public API.
//!
//! `data/draft-11.json` holds the three vectors of draft-connolly-cfrg-xwing-kem-11 appendix C,
//! copied from the RustCrypto `x-wing` 0.1.1 crate (`tests/test-vectors.json`, MIT OR
//! Apache-2.0). The X25519 vectors are from RFC 7748 sections 5.2 and 6.1.

use core::convert::Infallible;
use rand_core::{TryCryptoRng, TryRng, utils};
use serde::Deserialize;
use xwing_embedded::{
    Ciphertext, DalekX25519, DecapsulationKey, DecapsulationKeySlot, EncapsulationKey,
    ExpandedKeySlot, MlKem768, OtfMlKem768, RustCryptoMlKem768, X25519, X25519PublicKey,
    X25519SecretKey, XWing,
};

#[derive(Deserialize)]
struct Vector {
    #[serde(with = "hex")]
    seed: [u8; 32],
    #[serde(with = "hex")]
    eseed: Vec<u8>,
    #[serde(with = "hex")]
    ss: [u8; 32],
    #[serde(with = "hex")]
    sk: [u8; 32],
    #[serde(with = "hex")]
    pk: Vec<u8>,
    #[serde(with = "hex")]
    ct: Vec<u8>,
}

/// Decodes a hex string into an array.
fn h<const N: usize>(hex: &str) -> [u8; N] {
    hex::decode(hex).unwrap().try_into().unwrap()
}

/// Returns the given bytes in order, to replay `eseed`.
struct FixedRng<'a>(&'a [u8]);

impl TryRng for FixedRng<'_> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        utils::next_word_via_fill(self)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        utils::next_word_via_fill(self)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        let (head, tail) = self.0.split_at(dst.len());
        dst.copy_from_slice(head);
        self.0 = tail;
        Ok(())
    }
}

impl TryCryptoRng for FixedRng<'_> {}

#[test]
fn matches_draft_test_vectors() {
    draft_test_vectors::<OtfMlKem768>();
    draft_test_vectors::<RustCryptoMlKem768>();
}

/// The draft-11 vectors with the ML-KEM-768 `M`.
fn draft_test_vectors<M: MlKem768 + Default>() {
    let vectors: Vec<Vector> = serde_json::from_str(include_str!("data/draft-11.json")).unwrap();
    assert_eq!(vectors.len(), 3);
    let kem = &mut XWing::<M, DalekX25519>::default();
    for v in vectors {
        assert_eq!(v.seed, v.sk);
        let rng = &mut FixedRng(&v.sk);
        let mut slot = DecapsulationKeySlot::new();
        let secret_key = DecapsulationKey::generate(&mut slot, rng);
        assert!(rng.0.is_empty());
        let mut public = EncapsulationKey::from([0xff; 1216]);
        kem.encapsulation_key(secret_key, &mut public);
        assert_eq!(public.as_ref().as_slice(), v.pk);
        let mut slot = ExpandedKeySlot::new();
        let key = kem.expand(&mut slot, secret_key, &public).unwrap();

        let peer = kem.check(&public).unwrap();
        let mut ciphertext = Ciphertext::from([0xff; 1120]);
        let rng = &mut FixedRng(&v.eseed);
        let secret = kem.encapsulate(rng, &peer, &mut ciphertext);
        assert!(rng.0.is_empty());
        assert_eq!(ciphertext.as_ref().as_slice(), v.ct);
        assert_eq!(secret.expose_secret(), &v.ss);

        let ciphertext = Ciphertext::from(<[u8; 1120]>::try_from(v.ct).unwrap());
        assert_eq!(kem.decapsulate(&key, &ciphertext).expose_secret(), &v.ss);
    }
}

#[test]
fn dalek_matches_rfc_7748() {
    rfc_7748(&mut DalekX25519);
}

/// The RFC 7748 vectors with the X25519 `x`.
fn rfc_7748(x: &mut impl X25519) {
    // Section 5.2: (scalar, u, X25519(scalar, u))
    for (scalar, u, out) in [
        (
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        ),
        (
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
        ),
    ] {
        let secret = X25519SecretKey::new(h(scalar));
        let peer = X25519PublicKey::from(h::<32>(u));
        assert_eq!(x.shared_secret(&secret, &peer).expose_secret(), &h(out));
    }

    // Section 6.1
    let a = X25519SecretKey::new(h(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ));
    let b = X25519SecretKey::new(h(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    ));
    let public_a = x.public_key(&a);
    let public_b = x.public_key(&b);
    assert_eq!(
        public_a,
        X25519PublicKey::from(h::<32>(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        ))
    );
    assert_eq!(
        public_b,
        X25519PublicKey::from(h::<32>(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        ))
    );
    let k = h::<32>("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    assert_eq!(x.shared_secret(&a, &public_b).expose_secret(), &k);
    assert_eq!(x.shared_secret(&b, &public_a).expose_secret(), &k);

    // Section 5.2, iterated: `k, u = X25519(k, u), k` from `k = u = 9`
    let mut k = X25519PublicKey::BASE_POINT.into();
    let mut u = X25519PublicKey::BASE_POINT;
    for i in 1..=1000 {
        let next = *x
            .shared_secret(&X25519SecretKey::new(k), &u)
            .expose_secret();
        (k, u) = (next, k.into());
        match i {
            1 => assert_eq!(
                k,
                h("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
            ),
            1000 => assert_eq!(
                k,
                h("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
            ),
            _ => {}
        }
    }
}
