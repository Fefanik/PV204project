#pragma once
#include "frost.h"
#include "node.h"

#include <vector>
#include <string>
#include <iostream>
#include <iomanip>

class Coordinator {
public:
    Coordinator(uint16_t n, uint16_t k)
        : n_(n), k_(k)
    {
        frost_keygen(n_, k_);
    }

    bool sign(const std::string& message,
              const std::vector<Node>& nodes,
              unsigned char out_sig[64])
    {
        if (nodes.size() < k_) {
            std::cerr << "Not enough nodes\n";
            return false;
        }

        std::vector<uint16_t> ids;
        for (size_t i = 0; i < k_; i++)
            ids.push_back(nodes[i].id());

        int rc = frost_sign(ids.data(), ids.size(), message.c_str(), out_sig);
        return rc == 0;
    }

    bool getPublicKey(unsigned char out_pk[32]) {
        return frost_get_public_key(out_pk) == 0;
    }

private:
    uint16_t n_;
    uint16_t k_;
};