#include "coordinator.h"
#include "node.h"

#include <sodium.h>
#include <vector>
#include <iostream>
#include <cstdio>

bool verify_ed25519(const unsigned char pk[32],
                    const unsigned char sig[64],
                    const std::string& msg)
{
    return crypto_sign_verify_detached(
        sig,
        reinterpret_cast<const unsigned char*>(msg.data()),
        msg.size(),
        pk
    ) == 0;
}

int main() {
    if (sodium_init() < 0) {
        std::cerr << "libsodium init failed\n";
        return 1;
    }

    // Create coordinator (3 nodes, threshold 2)
    Coordinator coord(3, 2);

    // Create nodes
    std::vector<Node> nodes = {
        Node(1),
        Node(2),
        Node(3)
    };

    // Extract public key from FROST (32-byte Ed25519)
    unsigned char public_key[32];
    if (!coord.getPublicKey(public_key)) {
        std::cerr << "Failed to get public key\n";
        return 1;
    }

    std::string msg = "Hello threshold world!";
    unsigned char signature[64];

    // Produce real MPC signature
    if (!coord.sign(msg, nodes, signature)) {
        std::cerr << "Signing failed\n";
        return 1;
    }

    // Print info
    std::cout << "\n=== FROST Threshold Signature Demo ===\n";
    std::cout << "Message: " << msg << "\n";
    std::cout << "Signature: ";
    for (int i = 0; i < 64; i++) printf("%02x", signature[i]);
    std::cout << "\nPublic Key: ";
    for (int i = 0; i < 32; i++) printf("%02x", public_key[i]);
    std::cout << "\n";

    // Good message
    bool ok = verify_ed25519(public_key, signature, "Hello threshold world!");
    std::cout << "Verification,should be ok sh: " << (ok ? "OK" : "FAIL") << "\n";

    //Bad msg
    bool nok = verify_ed25519(public_key, signature, "Bad msg");
    std::cout << "Verification with bad ms: " << (nok ? "OK" : "FAIL") << "\n";

    //Bad pk
    unsigned char zero_pk[32] = {0};
    bool nok2 = verify_ed25519(zero_pk, signature, "Hello threshold world!");
    std::cout << "Verification with zero pk: " << (nok2 ? "OK" : "FAIL") << "\n";

    return 0;
}