//! Cross checks against the RustCrypto `x-wing` crate and between the ML-KEM-768 backends, and
//! the properties of the components. Each X-Wing test runs with both ML-KEM-768 backends.

use chacha20::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};
use x_wing::{Decapsulate, Decapsulator, KeyExport};
use xwing_embedded::{
    Ciphertext, DalekX25519, DecapsulationKey, DecapsulationKeySlot, EncapsulationKey,
    ExpandedKeySlot, InvalidEncapsulationKey, KeyMismatch, MlKem768, MlKemSharedSecret,
    OtfMlKem768, RustCryptoMlKem768, X25519, X25519PublicKey, X25519SecretKey, X25519SharedSecret,
    XWing,
};

/// X-Wing with the ML-KEM-768 `M` and `DalekX25519`.
fn xwing<M: MlKem768 + Default>() -> XWing<M, DalekX25519> {
    XWing::default()
}

/// Loads a copy of `seed` into `slot`.
fn load(slot: &mut DecapsulationKeySlot, seed: [u8; 32]) -> &DecapsulationKey {
    let mut seed = seed;
    DecapsulationKey::from_seed(slot, &mut seed)
}

/// The encapsulation key of `key`.
fn encapsulation_key_of<M: MlKem768, X: X25519>(
    kem: &mut XWing<M, X>,
    key: &DecapsulationKey,
) -> EncapsulationKey {
    let mut public = EncapsulationKey::from([0; 1216]);
    kem.encapsulation_key(key, &mut public);
    public
}

/// Decapsulates with the `x-wing` crate.
fn x_wing_decapsulate(seed: [u8; 32], ciphertext: &Ciphertext) -> [u8; 32] {
    let theirs = x_wing::DecapsulationKey::from(seed);
    let ciphertext = x_wing::Ciphertext::try_from(ciphertext.as_ref().as_slice()).unwrap();
    theirs.decapsulate(&ciphertext).into()
}

#[test]
fn matches_x_wing_crate() {
    matches_x_wing_crate_with::<OtfMlKem768>();
    matches_x_wing_crate_with::<RustCryptoMlKem768>();
}

fn matches_x_wing_crate_with<M: MlKem768 + Default>() {
    let kem = &mut xwing::<M>();
    for i in 0..8 {
        let rng = &mut ChaCha20Rng::from_seed([i; 32]);
        let mut seed = [0; 32];
        rng.fill_bytes(&mut seed);

        let mut slot = DecapsulationKeySlot::new();
        let secret_key = load(&mut slot, seed);
        let public = encapsulation_key_of(kem, secret_key);
        let mut key_slot = ExpandedKeySlot::new();
        let key = kem.expand(&mut key_slot, secret_key, &public).unwrap();
        let theirs = x_wing::DecapsulationKey::from(seed);
        assert_eq!(
            public.as_ref().as_slice(),
            &*theirs.encapsulation_key().to_bytes()
        );

        let peer = kem.check(&public).unwrap();
        let mut eseed = [0; 64];
        ChaCha20Rng::from_seed([i + 100; 32]).fill_bytes(&mut eseed);
        let mut ciphertext = Ciphertext::from([0; 1120]);
        let rng = &mut ChaCha20Rng::from_seed([i + 100; 32]);
        let secret = kem.encapsulate(rng, &peer, &mut ciphertext);
        let (their_ciphertext, their_secret) = theirs
            .encapsulation_key()
            .encapsulate_deterministic(&eseed.into());
        assert_eq!(ciphertext.as_ref().as_slice(), &*their_ciphertext);
        assert_eq!(secret.expose_secret().as_slice(), &*their_secret);
        assert_eq!(
            kem.decapsulate(&key, &ciphertext).expose_secret(),
            secret.expose_secret()
        );

        // Bits of ct_M, then of ct_X, including bit 255 of the X25519 u-coordinate
        for (at, bit) in [
            (0, 1),
            (500, 1),
            (1087, 1),
            (1088, 1),
            (1119, 1),
            (1119, 0x80),
        ] {
            let mut tampered = ciphertext.clone();
            tampered.as_mut()[at] ^= bit;
            let other = kem.decapsulate(&key, &tampered);
            assert_ne!(
                other.expose_secret(),
                secret.expose_secret(),
                "byte {at} bit {bit:#x}"
            );
            assert_eq!(
                kem.decapsulate(&key, &tampered).expose_secret(),
                other.expose_secret(),
                "byte {at} bit {bit:#x}"
            );
            assert_eq!(
                other.expose_secret(),
                &x_wing_decapsulate(seed, &tampered),
                "byte {at} bit {bit:#x}"
            );
        }

        // The combiner hashes pk_X as given, also when it is not canonical or of low order
        let mut own_x25519: [u8; 32] = public.as_ref()[1184..].try_into().unwrap();
        own_x25519[31] |= 0x80;
        let mut p = [0xff; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        for x25519 in [own_x25519, [0; 32], [0xff; 32], p] {
            let mut bytes = *public.as_ref();
            bytes[1184..].copy_from_slice(&x25519);
            let public = EncapsulationKey::from(bytes);
            let peer = kem.check(&public).unwrap();
            let rng = &mut ChaCha20Rng::from_seed([i + 100; 32]);
            let secret = kem.encapsulate(rng, &peer, &mut ciphertext);
            let theirs = x_wing::EncapsulationKey::try_from(bytes.as_slice()).unwrap();
            let (their_ciphertext, their_secret) = theirs.encapsulate_deterministic(&eseed.into());
            assert_eq!(ciphertext.as_ref().as_slice(), &*their_ciphertext);
            assert_eq!(secret.expose_secret().as_slice(), &*their_secret);
        }

        let mut other_slot = DecapsulationKeySlot::new();
        let other_secret_key = load(&mut other_slot, [i ^ 0xff; 32]);
        let other_public = encapsulation_key_of(kem, other_secret_key);
        let mut other_key_slot = ExpandedKeySlot::new();
        let other_key = kem
            .expand(&mut other_key_slot, other_secret_key, &other_public)
            .unwrap();
        assert_ne!(
            kem.decapsulate(&other_key, &ciphertext).expose_secret(),
            secret.expose_secret()
        );
    }
}

#[test]
fn expand_rejects_another_encapsulation_key() {
    expand_rejects_another_encapsulation_key_with::<OtfMlKem768>();
    expand_rejects_another_encapsulation_key_with::<RustCryptoMlKem768>();
}

fn expand_rejects_another_encapsulation_key_with<M: MlKem768 + Default>() {
    let kem = &mut xwing::<M>();
    let mut slot = DecapsulationKeySlot::new();
    let secret_key = load(&mut slot, [5; 32]);
    let own = encapsulation_key_of(kem, secret_key);
    // Bytes of pk_M, then of pk_X
    for at in [0, 1183, 1184, 1215] {
        let mut other = own.clone();
        other.as_mut()[at] ^= 1;
        assert_eq!(
            kem.expand(&mut ExpandedKeySlot::new(), secret_key, &other)
                .err(),
            Some(KeyMismatch),
            "byte {at}"
        );
    }
    assert!(
        kem.expand(&mut ExpandedKeySlot::new(), secret_key, &own)
            .is_ok()
    );
}

#[test]
fn accepts_all_zero_x25519() {
    accepts_all_zero_x25519_with::<OtfMlKem768>();
    accepts_all_zero_x25519_with::<RustCryptoMlKem768>();
}

fn accepts_all_zero_x25519_with<M: MlKem768 + Default>() {
    let kem = &mut xwing::<M>();
    let seed = [7; 32];
    let mut slot = DecapsulationKeySlot::new();
    let secret_key = load(&mut slot, seed);
    let public = encapsulation_key_of(kem, secret_key);
    let mut key_slot = ExpandedKeySlot::new();
    let key = kem.expand(&mut key_slot, secret_key, &public).unwrap();
    let mut ciphertext = Ciphertext::from([0x5a; 1120]);
    // u = 0 is a low-order point, so X25519 gives all zeros.
    ciphertext.as_mut()[1088..].fill(0);
    let secret = kem.decapsulate(&key, &ciphertext);
    assert_eq!(
        secret.expose_secret(),
        &x_wing_decapsulate(seed, &ciphertext)
    );
    let zero = DalekX25519.shared_secret(&X25519SecretKey::new([7; 32]), &[0; 32].into());
    assert_eq!(zero.expose_secret(), &[0; 32]);
}

#[test]
fn rejects_out_of_range_coefficient() {
    rejects_out_of_range_coefficient_with::<OtfMlKem768>();
    rejects_out_of_range_coefficient_with::<RustCryptoMlKem768>();
}

fn rejects_out_of_range_coefficient_with<M: MlKem768 + Default>() {
    let kem = &mut xwing::<M>();
    let mut public = encapsulation_key_of(kem, load(&mut DecapsulationKeySlot::new(), [1; 32]));
    public.as_mut()[1184..].fill(0xff);

    // Coefficient `i` is 12 bits at bit 12 * i, so even ones start on a byte and odd ones in
    // the middle of one.
    let set = |public: &EncapsulationKey, i: usize, value: u16| {
        let mut public = public.clone();
        let bytes = &mut public.as_mut()[i / 2 * 3..][..3];
        let pair = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]);
        let shift = 12 * (i % 2);
        let pair = pair & !(0xfff << shift) | u32::from(value) << shift;
        bytes.copy_from_slice(&pair.to_le_bytes()[..3]);
        public
    };
    for i in 0..768 {
        assert!(kem.check(&set(&public, i, 3328)).is_ok(), "{i}");
        for value in [3329, 4095] {
            assert_eq!(
                kem.check(&set(&public, i, value)).err(),
                Some(InvalidEncapsulationKey),
                "{i} {value}"
            );
        }
    }
}

/// Counts the calls into each method of a component and delegates to `inner`.
#[derive(Default)]
struct Counting<T, C> {
    inner: T,
    calls: C,
}

/// Calls into an [`MlKem768`].
#[derive(Debug, Default, PartialEq)]
struct MlKemCalls {
    encapsulation_key: usize,
    expand: usize,
    check: usize,
    encapsulate: usize,
    decapsulate: usize,
}

/// Calls into an [`X25519`].
#[derive(Debug, Default, PartialEq)]
struct X25519Calls {
    shared_secret: usize,
    public_key: usize,
}

impl<X: X25519> X25519 for Counting<X, X25519Calls> {
    fn shared_secret(
        &mut self,
        secret: &X25519SecretKey,
        peer: &X25519PublicKey,
    ) -> X25519SharedSecret {
        self.calls.shared_secret += 1;
        self.inner.shared_secret(secret, peer)
    }

    fn public_key(&mut self, secret: &X25519SecretKey) -> X25519PublicKey {
        self.calls.public_key += 1;
        self.inner.public_key(secret)
    }
}

impl<M: MlKem768> MlKem768 for Counting<M, MlKemCalls> {
    type KeySlot = M::KeySlot;
    type ExpandedKey<'a> = M::ExpandedKey<'a>;
    type CheckedKey<'k> = M::CheckedKey<'k>;

    const EMPTY_SLOT: M::KeySlot = M::EMPTY_SLOT;

    fn encapsulation_key(&mut self, seed: &mut [u8; 64], out: &mut [u8; 1184]) {
        self.calls.encapsulation_key += 1;
        self.inner.encapsulation_key(seed, out);
    }

    fn expand<'a>(
        &mut self,
        slot: &'a mut M::KeySlot,
        seed: &mut [u8; 64],
        own: &'a [u8; 1184],
    ) -> Result<M::ExpandedKey<'a>, KeyMismatch> {
        self.calls.expand += 1;
        self.inner.expand(slot, seed, own)
    }

    fn check<'k>(
        &mut self,
        key: &'k [u8; 1184],
    ) -> Result<M::CheckedKey<'k>, InvalidEncapsulationKey> {
        self.calls.check += 1;
        self.inner.check(key)
    }

    fn encapsulate(
        &mut self,
        peer: &M::CheckedKey<'_>,
        m: &[u8; 32],
        ciphertext: &mut [u8; 1088],
    ) -> MlKemSharedSecret {
        self.calls.encapsulate += 1;
        self.inner.encapsulate(peer, m, ciphertext)
    }

    fn decapsulate(
        &mut self,
        key: &M::ExpandedKey<'_>,
        ciphertext: &[u8; 1088],
    ) -> MlKemSharedSecret {
        self.calls.decapsulate += 1;
        self.inner.decapsulate(key, ciphertext)
    }
}

#[test]
fn components_are_swappable() {
    components_are_swappable_with::<OtfMlKem768>();
    components_are_swappable_with::<RustCryptoMlKem768>();
}

fn components_are_swappable_with<M: MlKem768 + Default>() {
    let kem = &mut XWing {
        ml_kem: Counting::<M, MlKemCalls>::default(),
        x25519: Counting::<DalekX25519, X25519Calls>::default(),
    };
    let ml_kem = |encapsulation_key, expand, check, encapsulate, decapsulate| MlKemCalls {
        encapsulation_key,
        expand,
        check,
        encapsulate,
        decapsulate,
    };
    let x25519 = |shared_secret, public_key| X25519Calls {
        shared_secret,
        public_key,
    };
    let mut slot = DecapsulationKeySlot::new();
    let secret_key = load(&mut slot, [3; 32]);

    let public = encapsulation_key_of(kem, secret_key);
    assert_eq!(kem.ml_kem.calls, ml_kem(1, 0, 0, 0, 0));
    assert_eq!(kem.x25519.calls, x25519(0, 1));

    let mut key_slot = ExpandedKeySlot::new();
    let key = kem.expand(&mut key_slot, secret_key, &public).unwrap();
    let peer = kem.check(&public).unwrap();
    assert_eq!(kem.ml_kem.calls, ml_kem(1, 1, 1, 0, 0));
    assert_eq!(kem.x25519.calls, x25519(0, 2));

    let mut ciphertext = Ciphertext::from([0; 1120]);
    let secret = kem.encapsulate(&mut ChaCha20Rng::from_seed([4; 32]), &peer, &mut ciphertext);
    assert_eq!(kem.ml_kem.calls, ml_kem(1, 1, 1, 1, 0));
    assert_eq!(kem.x25519.calls, x25519(1, 3));

    // Decapsulation does not expand the key again.
    let again = kem.decapsulate(&key, &ciphertext);
    assert_eq!(kem.ml_kem.calls, ml_kem(1, 1, 1, 1, 1));
    assert_eq!(kem.x25519.calls, x25519(2, 3));
    assert_eq!(again.expose_secret(), secret.expose_secret());

    let reference = &mut xwing::<RustCryptoMlKem768>();
    let mut reference_slot = ExpandedKeySlot::new();
    let reference_key = reference
        .expand(&mut reference_slot, secret_key, &public)
        .unwrap();
    assert_eq!(
        reference
            .decapsulate(&reference_key, &ciphertext)
            .expose_secret(),
        secret.expose_secret()
    );
}

#[test]
fn mlkem_otf_matches_ml_kem() {
    let (otf, reference) = (&mut OtfMlKem768, &mut RustCryptoMlKem768);
    for i in 0..=255 {
        let rng = &mut ChaCha20Rng::from_seed([i; 32]);
        let mut seed = [0; 64];
        rng.fill_bytes(&mut seed);
        let (mut public, mut reference_public) = ([0; 1184], [0xff; 1184]);
        otf.encapsulation_key(&mut seed.clone(), &mut public);
        reference.encapsulation_key(&mut seed.clone(), &mut reference_public);
        assert_eq!(public, reference_public, "seed {i}");

        let (mut slot, mut reference_slot) =
            (OtfMlKem768::EMPTY_SLOT, RustCryptoMlKem768::EMPTY_SLOT);
        let mut other = public;
        other[rng.next_u32() as usize % 1184] ^= 1 << (rng.next_u32() % 8);
        assert_eq!(
            otf.expand(&mut slot, &mut seed.clone(), &other).err(),
            Some(KeyMismatch)
        );
        assert_eq!(
            reference
                .expand(&mut reference_slot, &mut seed.clone(), &other)
                .err(),
            Some(KeyMismatch)
        );
        let key = otf.expand(&mut slot, &mut seed.clone(), &public).unwrap();
        let reference_key = reference
            .expand(&mut reference_slot, &mut seed.clone(), &public)
            .unwrap();
        let peer = otf.check(&public).unwrap();
        let reference_peer = reference.check(&public).unwrap();

        let mut m = [0; 32];
        rng.fill_bytes(&mut m);
        let (mut ciphertext, mut reference_ciphertext) = ([0; 1088], [0xff; 1088]);
        let secret = otf.encapsulate(&peer, &m, &mut ciphertext);
        let reference_secret =
            reference.encapsulate(&reference_peer, &m, &mut reference_ciphertext);
        assert_eq!(ciphertext, reference_ciphertext, "seed {i}");
        assert_eq!(secret.expose_secret(), reference_secret.expose_secret());
        assert_eq!(
            otf.decapsulate(&key, &ciphertext).expose_secret(),
            secret.expose_secret()
        );

        // Both give the same implicit rejection key
        let mut tampered = ciphertext;
        tampered[rng.next_u32() as usize % 1088] ^= 1 << (rng.next_u32() % 8);
        let rejected = otf.decapsulate(&key, &tampered);
        assert_ne!(rejected.expose_secret(), secret.expose_secret());
        assert_eq!(
            rejected.expose_secret(),
            reference
                .decapsulate(&reference_key, &tampered)
                .expose_secret(),
            "seed {i}"
        );

        // Both reject a coefficient of q or more
        let mut invalid = public;
        let at = rng.next_u32() as usize % 384 * 3;
        invalid[at] = 0xff;
        invalid[at + 1] |= 0x0f;
        assert_eq!(otf.check(&invalid).err(), Some(InvalidEncapsulationKey));
        assert_eq!(
            reference.check(&invalid).err(),
            Some(InvalidEncapsulationKey)
        );
    }
}

#[test]
fn dalek_matches_x25519_dalek() {
    let x = &mut DalekX25519;
    let rng = &mut ChaCha20Rng::from_seed([0; 32]);
    // Random scalars and u-coordinates, half with the top bit set, and `u = 2^256 - 1`, which is
    // p or more without the top bit
    for i in 0..256 {
        let (mut scalar, mut u) = ([0; 32], [0xff; 32]);
        rng.fill_bytes(&mut scalar);
        if i > 0 {
            rng.fill_bytes(&mut u);
        }
        let secret = x.shared_secret(&X25519SecretKey::new(scalar), &u.into());
        assert_eq!(secret.expose_secret(), &x25519_dalek::x25519(scalar, u));
    }
}
