#pragma once

#include <string>
#include <cstdint>
#include <stdexcept>

/**
 * @brief Configuration settings for the key generation process.
 */
struct KeygenConfig {
    uint16_t n = 0;             // Total number of nodes/participants
    uint16_t t = 0;             // Threshold of nodes required to sign
    std::string out_dir;        // Directory where the generated keys will be saved
    bool emit_c_array = false;  // Flag indicating if the public key package should be printed as a C array
};

/**
 * @brief Parses command-line arguments and returns a configuration struct.
 * 
 * @param argc The number of command-line arguments.
 * @param argv The array of command-line arguments.
 * @return KeygenConfig The populated configuration struct.
 * @throw std::invalid_argument If the arguments are insufficient or invalid.
 */
KeygenConfig parse_arguments(int argc, char* argv[]);

/**
 * @brief Orchestrates the key generation and saving logic.
 * 
 * @param config The parsed configuration parameters.
 * @throw std::runtime_error If the key generation process or file writing fails.
 */
void run_keygen(const KeygenConfig& config);