#ifndef SERVER_MAIN_H
#define SERVER_MAIN_H

#include <string>
#include <vector>

/**
 * Simulates a node signing a message with its secret key share.
 * @param node_id The ID of the current node
 * @param my_secret_share The string loaded from the node's .key file
 * @param message The payload (Hash + Timestamp) to sign
 * @return A string simulating a partial signature
 */
std::string dummy_sign_partial(int node_id, std::string my_secret_share, std::string message);

/**
 * Simulates the Orchestrator combining multiple partial signatures.
 * @param shares A vector containing the partial signature strings
 * @return A string simulating the final aggregated signature
 */
std::string dummy_aggregate(std::vector<std::string> shares);

#endif // SERVER_MAIN_H