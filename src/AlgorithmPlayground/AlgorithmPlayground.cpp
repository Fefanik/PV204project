


#include "AlgorithmPlatgorund.h"
#include <iostream>
#include <string>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>

std::string sha256(const std::string &input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)input.c_str(), input.size(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

class Node {
private:
    int id;
    std::string keyShare;

public:
    Node(int nodeId, const std::string& share)
        : id(nodeId), keyShare(share) {}

    std::string signPartial(const std::string& message) {
        return sha256(message + keyShare);
    }

    int getId() const {
        return id;
    }
};

int main(int argc, char* argv[]) {

    if (argc != 3) {
        std::cout << "Usage: ./node <node_id> <key_share>\n";
        return 1;
    }

    int nodeId = std::stoi(argv[1]);
    std::string keyShare = argv[2];

    Node node(nodeId, keyShare);

    std::string message;
    std::getline(std::cin, message);

    std::string partialSig = node.signPartial(message);

    std::cout << "Node " << node.getId() << " partial signature:\n";
    std::cout << partialSig << std::endl;

    return 0;
}