use frost_ed25519 as frost;

use frost::keys::{self, KeyPackage, PublicKeyPackage};
use frost::{round1, round2, SigningPackage, aggregate};
use frost::keys::IdentifierList;
use frost::Identifier;

use rand::rngs::OsRng;

use std::collections::BTreeMap;
use std::ffi::CStr;
use std::os::raw::{c_char, c_uchar};

// Demo storage (process-global). For production, use proper state handling.
static mut KEY_PACKAGES: Option<BTreeMap<Identifier, KeyPackage>> = None;
static mut PUBKEY_PACKAGE: Option<PublicKeyPackage> = None;

/// Trusted Dealer KeyGen
#[no_mangle]
pub extern "C" fn frost_keygen(max_signers: u16, min_signers: u16) {
    let mut rng = OsRng;

    let (shares, pubkey_package) = keys::generate_with_dealer(
        max_signers,
        min_signers,
        IdentifierList::Default,
        &mut rng,
    ).expect("keygen failed");

    let mut key_packages: BTreeMap<Identifier, KeyPackage> = BTreeMap::new();
    for (id, secret_share) in shares {
        let kp = KeyPackage::try_from(secret_share).expect("share verification failed");
        key_packages.insert(id, kp);
    }

    unsafe {
        KEY_PACKAGES = Some(key_packages);
        PUBKEY_PACKAGE = Some(pubkey_package);
    }
}

/// Full threshold signing
#[no_mangle]
pub extern "C" fn frost_sign(
    ids_ptr: *const u16,
    len: usize,
    message: *const c_char,
    out_sig64: *mut c_uchar,
) -> i32 {

    if ids_ptr.is_null() || message.is_null() || out_sig64.is_null() || len == 0 {
        return 1;
    }

    let msg = match unsafe { CStr::from_ptr(message).to_str() } {
        Ok(s) => s.as_bytes().to_vec(),
        Err(_) => return 2,
    };

    let key_packages = match unsafe { KEY_PACKAGES.as_ref() } {
        Some(m) => m,
        None => return 3,
    };

    let pubkey_package = match unsafe { PUBKEY_PACKAGE.as_ref() } {
        Some(p) => p,
        None => return 3,
    };

    let mut rng = OsRng;
    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = BTreeMap::new();

    for i in 0..len {
        let raw_id = unsafe { *ids_ptr.add(i) };

        let id: Identifier = match raw_id.try_into() {
            Ok(v) => v,
            Err(_) => return 4,
        };

        let kp = match key_packages.get(&id) {
            Some(k) => k,
            None => return 5,
        };

        let (nonces, commitments) =
            round1::commit(kp.signing_share(), &mut rng);

        nonces_map.insert(id, nonces);
        commitments_map.insert(id, commitments);
    }

    let signing_package = SigningPackage::new(commitments_map, &msg);

    let mut signature_shares = BTreeMap::new();
    for i in 0..len {
        let raw_id = unsafe { *ids_ptr.add(i) };

        let id: Identifier = match raw_id.try_into() {
            Ok(v) => v,
            Err(_) => return 4,
        };

        let kp = &key_packages[&id];
        let nonces = &nonces_map[&id];

        let sig_share = match round2::sign(&signing_package, nonces, kp) {
            Ok(s) => s,
            Err(_) => return 6,
        };
        signature_shares.insert(id, sig_share);
    }

    let final_sig = match aggregate(&signing_package, &signature_shares, pubkey_package) {
        Ok(s) => s,
        Err(_) => return 7,
    };

    let sig_bytes = final_sig.serialize();
    unsafe {
        std::ptr::copy_nonoverlapping(sig_bytes.as_ptr(), out_sig64, 64);
    }

    0
}

/// Export 32‑byte group public key
#[no_mangle]
pub extern "C" fn frost_get_public_key(out32: *mut c_uchar) -> i32 {
    if out32.is_null() { return 1; }

    let pubkey_package = unsafe {
        match PUBKEY_PACKAGE.as_ref() {
            Some(pk) => pk,
            None => return 2,
        }
    };

    let vk_bytes = pubkey_package.verifying_key().serialize();

    unsafe {
        std::ptr::copy_nonoverlapping(vk_bytes.as_ptr(), out32, 32);
    }

    0
}
