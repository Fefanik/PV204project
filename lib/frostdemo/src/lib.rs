use frost_ed25519 as frost;

use frost::keys::{self, KeyPackage, PublicKeyPackage, IdentifierList};
use frost::{round1, round2, SigningPackage, aggregate};
use frost::Identifier;

use rand::rngs::OsRng;
use std::collections::BTreeMap;
use std::os::raw::c_uchar;

// ---------------------------------------------------------------------------
// GLOBAL RAM STATE — ONE KEY PER PROCESS (NODE)
// ---------------------------------------------------------------------------

static mut KEY_PACKAGE: Option<KeyPackage> = None;
static mut PUBKEY_PACKAGE: Option<PublicKeyPackage> = None;
static mut R1_NONCES: Option<round1::SigningNonces> = None;


// ============================
// 1) Trusted Dealer Keygen
// ============================
//
// Called only by the orchestrator, not nodes.
// Returns serialized keyshares and pubkey through C++.
//
#[no_mangle]
pub extern "C" fn frost_keygen(
    n: u16,
    t: u16,
    out_key_ptrs: *mut *mut u8,
    out_key_lens: *mut usize,
    out_pub_ptr: *mut *mut u8,
    out_pub_len: *mut usize,
) -> i32 {
    if out_key_ptrs.is_null() || out_key_lens.is_null()
        || out_pub_ptr.is_null() || out_pub_len.is_null() {
        return 1;
    }

    let mut rng = OsRng;

    let (shares, pubkey_pkg) =
        match keys::generate_with_dealer(n, t, IdentifierList::Default, &mut rng) {
            Ok(v) => v,
            Err(_) => return 2,
        };

    // serialize pubkey_pkg
    let pub_bytes = match bincode::serialize(&pubkey_pkg) {
        Ok(v) => v,
        Err(_) => return 3,
    };

    unsafe {
        let ptr = libc::malloc(pub_bytes.len()) as *mut u8;
        if ptr.is_null() { return 4; }
        std::ptr::copy_nonoverlapping(pub_bytes.as_ptr(), ptr, pub_bytes.len());
        *out_pub_ptr = ptr;
        *out_pub_len = pub_bytes.len();
    }

    // Each secret share -> KeyPackage -> serialize
    for (i, (_id, share)) in shares.into_iter().enumerate() {
        let kp = match KeyPackage::try_from(share) {
            Ok(v) => v,
            Err(_) => return 5,
        };

        let kp_bytes = match bincode::serialize(&kp) {
            Ok(v) => v,
            Err(_) => return 6,
        };

        unsafe {
            let ptrs = out_key_ptrs.add(i);
            let lens = out_key_lens.add(i);

            let ptr = libc::malloc(kp_bytes.len()) as *mut u8;
            if ptr.is_null() { return 7; }
            std::ptr::copy_nonoverlapping(kp_bytes.as_ptr(), ptr, kp_bytes.len());
            *ptrs = ptr;
            *lens = kp_bytes.len();
        }
    }

    0
}

// ============================
// 2) Load KeyShare (per node)
// ============================
//
// Node receives its keyshare bytes from C++.
//
#[no_mangle]
pub extern "C" fn frost_load_keyshare(
    key_ptr: *const u8,
    key_len: usize,
    pub_ptr: *const u8,
    pub_len: usize,
) -> i32 {
    if key_ptr.is_null() || pub_ptr.is_null() { return 1; }

    let key_bytes = unsafe { std::slice::from_raw_parts(key_ptr, key_len) };
    let pub_bytes = unsafe { std::slice::from_raw_parts(pub_ptr, pub_len) };

    let kp: KeyPackage = match bincode::deserialize(key_bytes) {
        Ok(v) => v,
        Err(_) => return 2,
    };

    let pp: PublicKeyPackage = match bincode::deserialize(pub_bytes) {
        Ok(v) => v,
        Err(_) => return 3,
    };

    unsafe {
        KEY_PACKAGE = Some(kp);
        PUBKEY_PACKAGE = Some(pp);
    }

    0
}


// ============================
// 3) Round 1: Commitments
// ============================
//
// Node generates nonces & commitments for itself.
//
#[no_mangle]
pub extern "C" fn frost_round1(
    out_ptr: *mut *mut u8,
    out_len: *mut usize
) -> i32 {
    if out_ptr.is_null() || out_len.is_null() { return 1; }

    let kp = unsafe { KEY_PACKAGE.as_ref() }.ok_or(2).unwrap();

    let mut rng = OsRng;
    let (nonces, commits) = round1::commit(kp.signing_share(), &mut rng);

    unsafe {
        R1_NONCES = Some(nonces);
    }

    // produce map: {id -> commit}
    let id = kp.identifier();
    let mut map = BTreeMap::new();
    map.insert(id, commits);

    let bytes = match bincode::serialize(&map) { Ok(v)=>v, Err(_)=>return 3 };

    unsafe {
        let p = libc::malloc(bytes.len()) as *mut u8;
        if p.is_null() { return 4; }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
        *out_ptr = p;
        *out_len = bytes.len();
    }

    0
}


// ============================
// 4) Round 2: Signature Share
// ============================
//
// Node consumes its own nonces + SigningPackage.
//
#[no_mangle]
pub extern "C" fn frost_round2(
    pkg_ptr: *const u8,
    pkg_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if pkg_ptr.is_null() || out_ptr.is_null() || out_len.is_null() { return 1; }

    let kp = unsafe { KEY_PACKAGE.as_ref() }.ok_or(2).unwrap();
    let nonces = unsafe { R1_NONCES.take() }.ok_or(3).unwrap();

    let pkg_bytes = unsafe { std::slice::from_raw_parts(pkg_ptr, pkg_len) };
    let signing_pkg: SigningPackage = match bincode::deserialize(pkg_bytes) {
        Ok(v) => v,
        Err(_) => return 4,
    };

    // compute signature share
    let share = match round2::sign(&signing_pkg, &nonces, kp) {
        Ok(v) => v,
        Err(_) => return 5,
    };

    let id = kp.identifier();
    let mut map = BTreeMap::new();
    map.insert(id, share);

    let bytes = match bincode::serialize(&map) { Ok(v)=>v, Err(_)=>return 6 };

    unsafe {
        let p = libc::malloc(bytes.len()) as *mut u8;
        if p.is_null() { return 7; }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
        *out_ptr = p;
        *out_len = bytes.len();
    }

    0
}


// ============================
// 5) Build SigningPackage (orchestrator)
// ============================
//
// Combine all commitment maps + message.
//
#[no_mangle]
pub extern "C" fn frost_build_signing_package(
    maps_ptrs: *const *const u8,
    maps_lens: *const usize,
    count: usize,
    msg_ptr: *const u8,
    msg_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize
) -> i32 {
    if maps_ptrs.is_null() || maps_lens.is_null()
        || msg_ptr.is_null() || out_ptr.is_null() || out_len.is_null() {
        return 1;
    }

    let ptrs = unsafe { std::slice::from_raw_parts(maps_ptrs, count) };
    let lens = unsafe { std::slice::from_raw_parts(maps_lens, count) };
    let msg  = unsafe { std::slice::from_raw_parts(msg_ptr, msg_len) };

    let mut all = BTreeMap::<Identifier, round1::SigningCommitments>::new();

    for i in 0..count {
        let data = unsafe { std::slice::from_raw_parts(ptrs[i], lens[i]) };
        let map: BTreeMap<Identifier, round1::SigningCommitments> =
            match bincode::deserialize(data) {
                Ok(m) => m,
                Err(_) => return 2,
            };
        for (id, c) in map {
            all.insert(id, c);
        }
    }

    let pkg = SigningPackage::new(all, msg);
    let bytes = match bincode::serialize(&pkg) { Ok(v)=>v, Err(_)=>return 3 };

    unsafe {
        let p = libc::malloc(bytes.len()) as *mut u8;
        if p.is_null() { return 4; }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
        *out_ptr = p;
        *out_len = bytes.len();
    }

    0
}


// ============================
// 6) Aggregate final signature (orchestrator)
// ============================
//
#[no_mangle]
pub extern "C" fn frost_aggregate(
    pkg_ptr: *const u8,
    pkg_len: usize,
    shares_ptr: *const u8,
    shares_len: usize,
    out64: *mut c_uchar,
) -> i32 {
    if pkg_ptr.is_null() || shares_ptr.is_null() || out64.is_null() {
        return 1;
    }

    let pub_pkg = unsafe { PUBKEY_PACKAGE.as_ref() }.ok_or(2).unwrap();

    let pkg_bytes = unsafe { std::slice::from_raw_parts(pkg_ptr, pkg_len) };
    let signing_pkg: SigningPackage = match bincode::deserialize(pkg_bytes) {
        Ok(v) => v,
        Err(_) => return 3,
    };

    let share_bytes = unsafe { std::slice::from_raw_parts(shares_ptr, shares_len) };
    let shares: BTreeMap<Identifier, round2::SignatureShare> =
        match bincode::deserialize(share_bytes) {
            Ok(v) => v,
            Err(_) => return 4,
        };

    let final_sig = match aggregate(&signing_pkg, &shares, pub_pkg) {
        Ok(v) => v,
        Err(_) => return 5,
    };

    let bytes = match final_sig.serialize() {
        Ok(v) => v,
        Err(_) => return 6,
    };

    if bytes.len() != 64 { return 7; }

    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out64, 64);
    }

    0
}

#[no_mangle]
pub extern "C" fn frost_merge_sigshare_maps(
    maps_ptrs: *const *const u8,
    maps_lens: *const usize,
    count: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if maps_ptrs.is_null() || maps_lens.is_null() || out_ptr.is_null() || out_len.is_null() {
        return 1;
    }
    let ptrs = unsafe { std::slice::from_raw_parts(maps_ptrs, count) };
    let lens = unsafe { std::slice::from_raw_parts(maps_lens, count) };
    let mut combined = std::collections::BTreeMap::<frost::Identifier, round2::SignatureShare>::new();

    for i in 0..count {
        let data = unsafe { std::slice::from_raw_parts(ptrs[i], lens[i]) };
        let one: std::collections::BTreeMap<frost::Identifier, round2::SignatureShare> =
            match bincode::deserialize(data) { Ok(v)=>v, Err(_)=>return 2 };
        for (id, s) in one { combined.insert(id, s); }
    }

    let bytes = match bincode::serialize(&combined) { Ok(v)=>v, Err(_)=>return 3 };
    unsafe {
        let p = libc::malloc(bytes.len()) as *mut u8;
        if p.is_null() { return 4; }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
        *out_ptr = p;
        *out_len = bytes.len();
    }
    0
}


#[no_mangle]
pub extern "C" fn frost_verify(
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
    sig_len: usize,
    pk_pkg_ptr: *const u8,
    pk_pkg_len: usize,
) -> i32 {
    if msg_ptr.is_null() || sig_ptr.is_null() || pk_pkg_ptr.is_null() {
        return 1; // null input
    }
    if sig_len != 64 {
        return 2; // signature must be exactly 64 bytes
    }

    let msg        = unsafe { std::slice::from_raw_parts(msg_ptr, msg_len) };
    let sig_bytes  = unsafe { std::slice::from_raw_parts(sig_ptr, sig_len) };
    let pk_pkg_raw = unsafe { std::slice::from_raw_parts(pk_pkg_ptr, pk_pkg_len) };

    // Deserialize PublicKeyPackage using the same bincode you use elsewhere
    let pub_pkg: frost::keys::PublicKeyPackage = match bincode::deserialize(pk_pkg_raw) {
        Ok(v) => v,
        Err(_) => return 3, // bad public key package encoding
    };

    // Convert 64 raw bytes into the FROST signature type
    let mut sig64 = [0u8; 64];
    sig64.copy_from_slice(sig_bytes);
    let signature = match frost::Signature::deserialize(&sig64) {
        Ok(s) => s,
        Err(_) => return 4, // bad signature encoding
    };

    // Verify against the verifying key contained in the PublicKeyPackage
    let vk = pub_pkg.verifying_key();
    match vk.verify(msg, &signature) {
        Ok(()) => 0, // VALID
        Err(_) => 5, // INVALID
    }
}




