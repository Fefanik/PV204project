#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

    // --- Orchestrator-only ---
    int frost_keygen(uint16_t n, uint16_t t,
                     uint8_t** out_key_ptrs /* array n */, size_t* out_key_lens /* array n */,
                     uint8_t** out_pub_ptr, size_t* out_pub_len);

    int frost_build_signing_package(
        const uint8_t* const* commit_maps, const size_t* commit_lens, size_t count,
        const uint8_t* msg, size_t msg_len,
        uint8_t** out_pkg_ptr, size_t* out_pkg_len);

    int frost_merge_sigshare_maps(
        const uint8_t* const* share_maps, const size_t* share_lens, size_t count,
        uint8_t** out_ptr, size_t* out_len);

    int frost_aggregate(
        const uint8_t* pkg_ptr, size_t pkg_len,
        const uint8_t* shares_ptr, size_t shares_len,
        uint8_t* out_sig64 /* 64 bytes */);
    int frost_merge_sigshare_maps(
        const uint8_t* const* share_maps, const size_t* share_lens, size_t count,
        uint8_t** out_ptr, size_t* out_len);

    // --- Node-only ---
    int frost_load_keyshare(const uint8_t* key_ptr, size_t key_len,
                            const uint8_t* pub_ptr, size_t pub_len);

    int frost_round1(uint8_t** out_commit_map, size_t* out_len);

    int frost_round2(const uint8_t* signing_pkg, size_t signing_pkg_len,
                     uint8_t** out_share_map, size_t* out_len);
#ifdef __cplusplus
}
#endif