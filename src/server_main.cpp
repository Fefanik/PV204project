// src/server_main.cpp
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <thread>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <cstdlib>

#include "httplib.h"
#include "json.hpp"
#include "frost_ffi.h"
#include "base64.h"
#include <openssl/sha.h>

using json = nlohmann::json;

std::string sha256(const std::string &input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.data()),
           input.size(), hash);

    std::string out;
    out.reserve(SHA256_DIGEST_LENGTH * 2);
    static const char* hex = "0123456789abcdef";
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        out.push_back(hex[(hash[i] >> 4) & 0xF]);
        out.push_back(hex[hash[i] & 0xF]);
    }
    return out;
}

json build_ceritiface(const std::string& my_pub_key, int my_id) {
    std::string pub_key_b64 = b64enc(
        reinterpret_cast<const uint8_t*>(my_pub_key.data()),
        my_pub_key.size()
    );

    std::string cert_fingerprint = sha256(
        std::to_string(my_id) + pub_key_b64
    );

    return {
        {"node_id", my_id},
        {"pub_key_b64", pub_key_b64},
        {"fingerprint", cert_fingerprint}
    };
}

struct RustBuf { uint8_t* p=nullptr; size_t n=0; ~RustBuf(){ if(p) std::free(p); } };

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: ./server_main <port> <node_id> <key_file> <pub_key_file> [peer_urls...]\n";
        return 1;
    }
    std::cout.setf(std::ios::unitbuf);

    int my_port = std::stoi(argv[1]);
    int my_id = std::stoi(argv[2]);
    std::string key_file_path = argv[3];
    std::string pub_key_file_path = argv[4];

    std::vector<std::string> peers;
    for(int i = 5; i < argc; i++) {
        peers.push_back(argv[i]);
    }

    // Load Secret Key
    std::ifstream key_file(key_file_path, std::ios::binary);
    while (!key_file.is_open()) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        key_file.open(key_file_path, std::ios::binary);
    }
    std::string my_secret_share((std::istreambuf_iterator<char>(key_file)),
                                 std::istreambuf_iterator<char>());

    // Load Public Key
    std::ifstream pub_key_file(pub_key_file_path, std::ios::binary);
    while (!pub_key_file.is_open()) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        pub_key_file.open(pub_key_file_path, std::ios::binary);
    }
    std::string my_pub_key((std::istreambuf_iterator<char>(pub_key_file)),
                            std::istreambuf_iterator<char>());
    json certificate = build_ceritiface(my_pub_key, my_id);

    std::cout << "[Node " << my_id << "] Keys loaded successfully! Sec: "
              << my_secret_share.length() << " bytes, Pub: " << my_pub_key.length() << " bytes.\n";

    // Hand off both keys to Rust FROST
    if (frost_load_keyshare(
            reinterpret_cast<const uint8_t*>(my_secret_share.data()),
            my_secret_share.size(),
            reinterpret_cast<const uint8_t*>(my_pub_key.data()),
            my_pub_key.size()) != 0) {
        std::cerr << "[Node " << my_id << "] frost_load_keyshare failed.\n";
        return 1;
    }

    httplib::Server svr;

    svr.Post("/round1_commitments", [my_id](const httplib::Request& req, httplib::Response& res) {
        RustBuf out;
        if (frost_round1(&out.p, &out.n) != 0) {
            res.status = 500; res.set_content("{\"error\":\"round1 failed\"}", "application/json"); return;
        }
        json jr = { {"node_id", my_id}, {"commit_map_b64", b64enc(out.p, out.n)} };
        res.set_content(jr.dump(), "application/json");
    });

    svr.Post("/sign_share", [my_id](const httplib::Request &req, httplib::Response &res) {
        auto jr = json::parse(req.body);
        if (!jr.contains("signing_package_b64")) {
            res.status=400; res.set_content("{\"error\":\"expected signing_package_b64\"}", "application/json"); return;
        }
        auto sp = b64dec(jr["signing_package_b64"].get<std::string>());

        RustBuf out;
        if (frost_round2(sp.data(), sp.size(), &out.p, &out.n) != 0) {
            res.status = 500; res.set_content("{\"error\":\"round2 failed\"}", "application/json"); return;
        }
        json j = { {"node_id", my_id}, {"share_map_b64", b64enc(out.p, out.n)} };
        res.set_content(j.dump(), "application/json");
    });

    svr.Post("/timestamp",[my_id, my_pub_key, &peers, certificate](const httplib::Request &req, httplib::Response &res) {
        auto json_req = json::parse(req.body);
        std::string document_hash = json_req["document_hash"];

        auto now = std::chrono::system_clock::now();
        std::time_t current_time = std::chrono::system_clock::to_time_t(now);
        std::string time_str = std::to_string(current_time);

        std::string payload_to_sign = document_hash + "_TIME_" + time_str;
        std::cout << "\n[Orchestrator] Starting distributed signature for payload: "
                  << payload_to_sign << "\n";

        // -------- Round 1 --------
        std::vector<std::vector<uint8_t>> commit_maps;
        {
            RustBuf out;
            if (frost_round1(&out.p, &out.n) != 0) { res.status=500; res.set_content("{\"error\":\"self round1 failed\"}", "application/json"); return; }
            commit_maps.emplace_back(out.p, out.p + out.n);
        }
        for (const auto& peer_url : peers) {
            httplib::Client cli(peer_url);
            if (auto r = cli.Post("/round1_commitments", "{}", "application/json")) {
                if (r->status != 200) { res.status=500; res.set_content("{\"error\":\"peer round1\"}", "application/json"); return; }
                auto jr = json::parse(r->body);
                commit_maps.emplace_back(b64dec(jr["commit_map_b64"]));
            }
        }
        if (commit_maps.empty()) { res.status=400; res.set_content("{\"error\":\"no commitments\"}","application/json"); return; }

        std::vector<const uint8_t*> cm_ptrs; std::vector<size_t> cm_lens;
        for (auto& v: commit_maps){ cm_ptrs.push_back(v.data()); cm_lens.push_back(v.size()); }

        RustBuf sp;
        {
            std::vector<uint8_t> msg(payload_to_sign.begin(), payload_to_sign.end());
            if (frost_build_signing_package(cm_ptrs.data(), cm_lens.data(), cm_ptrs.size(),
                                            msg.data(), msg.size(), &sp.p, &sp.n) != 0) {
                res.status=500; res.set_content("{\"error\":\"build signing package failed\"}", "application/json"); return;
            }
        }

        // -------- Round 2 --------
        std::vector<std::vector<uint8_t>> share_maps;
        {
            RustBuf out;
            if (frost_round2(sp.p, sp.n, &out.p, &out.n) != 0) { res.status=500; res.set_content("{\"error\":\"self round2 failed\"}", "application/json"); return; }
            share_maps.emplace_back(out.p, out.p + out.n);
        }
        {
            std::string sp_b64 = b64enc(sp.p, sp.n);
            for (const auto& peer_url : peers) {
                httplib::Client cli(peer_url);
                json body = { {"signing_package_b64", sp_b64} };
                if (auto r = cli.Post("/sign_share", body.dump(), "application/json")) {
                    if (r->status != 200) { res.status=500; res.set_content("{\"error\":\"peer round2\"}", "application/json"); return; }
                    auto jr = json::parse(r->body);
                    share_maps.emplace_back(b64dec(jr["share_map_b64"]));
                }
            }
        }

        std::vector<const uint8_t*> sh_ptrs; std::vector<size_t> sh_lens;
        for (auto& v: share_maps){ sh_ptrs.push_back(v.data()); sh_lens.push_back(v.size()); }

        RustBuf merged;
        if (frost_merge_sigshare_maps(sh_ptrs.data(), sh_lens.data(), sh_ptrs.size(), &merged.p, &merged.n) != 0) {
            res.status=500; res.set_content("{\"error\":\"merge shares failed\"}", "application/json"); return;
        }

        std::vector<uint8_t> sig64(64);
        if (frost_aggregate(sp.p, sp.n, merged.p, merged.n, sig64.data()) != 0) {
            res.status=500; res.set_content("{\"error\":\"aggregate failed\"}", "application/json"); return;
        }

        json final_response = {
            {"status", "success"},
            {"timestamp", current_time},
            {"payload_signed", payload_to_sign},
            {"final_signature_b64", b64enc(sig64.data(), sig64.size())},
            {"public_key_b64", b64enc(reinterpret_cast<const uint8_t*>(my_pub_key.data()), my_pub_key.size())}
        };

        final_response["certificate"] = certificate;

        res.set_content(final_response.dump(), "application/json");
    });

    std::cout << "Starting Node " << my_id << " on port " << my_port << "...\n";
    svr.listen("0.0.0.0", my_port);
    return 0;
}