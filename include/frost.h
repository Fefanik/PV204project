#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

    void frost_keygen(uint16_t max_signers, uint16_t min_signers);

    int frost_sign(const uint16_t* ids,
                   size_t ids_len,
                   const char* message,
                   unsigned char* out_sig64);

    int frost_get_public_key(unsigned char* out_pk32);

#ifdef __cplusplus
}
#endif