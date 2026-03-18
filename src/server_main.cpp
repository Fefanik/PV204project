#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <thread>
#include <chrono>

#include "server_main.h" 

#include "httplib.h"
#include "json.hpp"

using json = nlohmann::json;

// --- DUMMY CRYPTO ---
std::string dummy_sign_partial(int node_id, std::string my_secret_share, std::string message) {
    return "sig_[Node:" + std::to_string(node_id) + "|Key:" + my_secret_share + "|Msg:" + message + "]";
}
std::string dummy_aggregate(std::vector<std::string> shares) {
    std::string final_sig = "FINAL_SIG:[";
    for(auto& s : shares) final_sig += s + ",";
    return final_sig + "]";
}
// --- DUMMY CRYPTO ---

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: ./node_app <port> <node_id> <key_file>[peer_urls...]\n";
        return 1;
    }

    int my_port = std::stoi(argv[1]);
    int my_id = std::stoi(argv[2]);
    std::string key_file_path = argv[3];
    
    std::vector<std::string> peers;
    for(int i = 4; i < argc; i++) {
        peers.push_back(argv[i]);
    }

    // Key assignment process on node startup
    std::cout << "[Node " << my_id << "] Waiting for key file at: " << key_file_path << "...\n";
    std::ifstream key_file(key_file_path);
    
    // Loop endlessly every 2 seconds until the file appears
    while (!key_file.is_open()) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        key_file.open(key_file_path);
    }

    // Read the secret key
    std::string my_secret_share((std::istreambuf_iterator<char>(key_file)), std::istreambuf_iterator<char>());
    std::cout << "[Node " << my_id << "] Key loaded successfully! Length: " << my_secret_share.length() << " characters.\n";


    httplib::Server svr;

    // Node mode
    svr.Post("/sign_share", [my_id, my_secret_share](const httplib::Request &req, httplib::Response &res) {
        auto json_req = json::parse(req.body);
        std::string message = json_req["message"];

        // Sign it using node's specific secret key loaded from the file
        std::string my_partial_sig = dummy_sign_partial(my_id, my_secret_share, message);

        json json_res = {
            {"node_id", my_id},
            {"partial_signature", my_partial_sig}
        };
        res.set_content(json_res.dump(), "application/json");
    });


    // Orchestrator mode
    svr.Post("/timestamp",[my_id, my_secret_share, &peers](const httplib::Request &req, httplib::Response &res) {
        auto json_req = json::parse(req.body);
        std::string document_hash = json_req["document_hash"];
        
        // Get the Unix timestamp
        auto now = std::chrono::system_clock::now();
        std::time_t current_time = std::chrono::system_clock::to_time_t(now);
        std::string time_str = std::to_string(current_time);

        // Combine the document hash and the timestamp
        std::string payload_to_sign = document_hash + "_TIME_" + time_str;
        std::cout << "\n[Orchestrator] Starting distributed signature for payload: " << payload_to_sign << "\n";

        std::vector<std::string> collected_shares;

        // Sign my own share
        collected_shares.push_back(dummy_sign_partial(my_id, my_secret_share, payload_to_sign));

        // Contact the peers
        for (const auto& peer_url : peers) {
            httplib::Client cli(peer_url);
            json payload = {{"message", payload_to_sign}};
            
            if (auto cli_res = cli.Post("/sign_share", payload.dump(), "application/json")) {
                auto peer_json = json::parse(cli_res->body);
                collected_shares.push_back(peer_json["partial_signature"]);
            }
        }

        // Aggregate all the partial keys
        std::string final_signature = dummy_aggregate(collected_shares);

        // Return the final timestamp receipt
        json final_response = {
            {"status", "success"},
            {"timestamp", current_time},
            {"payload_signed", payload_to_sign},
            {"final_signature", final_signature}
        };
        res.set_content(final_response.dump(), "application/json");
    });

    std::cout << "Starting Node " << my_id << " on port " << my_port << "...\n";
    svr.listen("0.0.0.0", my_port);

    return 0;
}