# PV204 Project: Trusted Timestamping Server

A distributed, command-line implementation of a trusted timestamping service utilizing FROST (Flexible Round-Optimized Schnorr Threshold signatures).

## Project Overview

This project implements a secure multi-party computation (MPC) architecture to eliminate single points of failure when issuing cryptographic timestamps. It operates on a dynamic k-of-n threshold system.

### Implemented Features:

- **Dynamic k-of-n threshold cryptography:** The network securely signs documents as long as a minimum threshold (k) of nodes is online.
- **Trust on first use (TOFU) certificate pinning:** The client prevents man-in-the-middle (MITM) attacks by pinning the server's public key fingerprint upon the first successful stamp.
- **Rust FFI integration:** C++ HTTP orchestrator nodes interfaced with memory-safe Rust cryptographic primitives (`ZcashFoundation/frost`).
- **Trusted dealer key generation:** A standalone CLI utility (`keygen`) to generate cryptographic key shares for the network.
- **Automated CI/CD pipeline:** Integrated GoogleTest unit testing, python-based E2E dynamic fault-tolerance tests, Valgrind memory analysis, and Semgrep static application security testing (SAST).

## Project Structure

```text
.
├── .github/workflows/
│   └── integration.yml       # CI/CD Pipeline (SAST, Valgrind, E2E tests)
├── include/                  # C++ Header files
│   ├── base64.h
│   ├── client_cli.h
│   ├── crypto_utils.h
│   ├── frost_ffi.h
│   └── keygen.h
├── lib/
│   ├── frostdemo/            # Rust FROST library source
│   ├── httplib.h             # C++ HTTP server/client library
│   └── json.hpp              # JSON parsing library
├── src/                      # C++ Implementation files
│   ├── base64.cpp
│   ├── client_cli.cpp        # Client stamping & verifying logic
│   ├── crypto_utils.cpp      # SHA-256 hashing utilities
│   ├── keygen_main.cpp       # Trusted dealer entry point
│   ├── keygen.cpp
│   ├── server_main.cpp       # Node orchestrator & FROST HTTP logic
│   └── verify_cli.cpp        # Standalone verification tool
├── tests/                    # GoogleTest Unit Tests
│   ├── test_base64.cpp
│   └── test_crypto.cpp
├── CMakeLists.txt            # CMake build system configuration
├── docker_generator.py       # Dynamic docker-compose topology generator
├── Dockerfile                # Multi-stage C++/Rust container definition
└── README.md                 # This documentation file
```

---

## Getting started

### Prerequisites

- A C++17 compatible compiler (GCC or Clang)
- CMake (>= 3.20)
- Rust & Cargo
- Docker & Docker Compose
- Python 3
- OpenSSL (`libssl-dev`) & Libsodium (`libsodium-dev`)

### Cloning the repository

Clone the repository using Git:

```bash
git clone https://github.com/Fefanik/PV204project.git
cd PV204project
```

### Building the project

The project uses CMake for its C++ build system and Cargo for its Rust libraries.

```bash
# 1. Compile the Rust library
cd lib/frostdemo
cargo build --release
cd ../..

# 2. Generate the CMake build system
cmake -S . -B build -G Ninja

# 3. Compile the applications
cmake --build build --parallel $(nproc)
```

The resulting executables (`client_cli`, `server_main`, `keygen`, `verify_cli`, `unit_tests`) will be located in the `build/` directory.

---

## Network configuration & execution

To support arbitrary threshold settings, the network configuration is generated dynamically.

### 1. Generate the Docker network

Use the Python generator to create a network topology.
_Usage:_ `python3 docker_generator.py <total_nodes> <threshold>`

```bash
# Example: Generate a 4-of-5 network
python3 docker_generator.py 5 4
```

### 2. Start the backend cluster

This will automatically execute the `setup_keys` job and start the nodes.

```bash
docker compose up --build -d
```

---

## Command line arguments & usage

### Client CLI (`client_cli`)

The client module interacts with the backend to request timestamps and verify them locally.

| Command  | Arguments               | Description                                                                                                                                                         |
| :------- | :---------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `stamp`  | `<file> [server_url]`   | Hashes the file, requests a timestamp from the network, pins the server's certificate locally, and saves a receipt. Server URL defaults to `http://localhost:8081`. |
| `verify` | `<file> <receipt.json>` | Cryptographically verifies the timestamped signature against the file hash and checks the pinned certificate for tampering.                                         |

**Example usage:**

```bash
# 1. Create a test file
echo "Test data" > my_document.txt

# 2. Request a timestamp
./build/client_cli stamp my_document.txt http://localhost:8081

# 3. Verify the signature
./build/client_cli verify my_document.txt my_document.txt.receipt.json
```

### Standalone verifier (`verify_cli`)

A low-level debugging tool that skips JSON and certificate parsing, verifying raw Base64 inputs directly.

- **Usage:** `./build/verify_cli <payload_signed> <final_signature_b64> <public_key_b64>`

### Trusted dealer (`keygen`)

_Automatically run by Docker during network setup, but available for local use._

- **Usage:** `./build/keygen <n> <t> <out_dir>`

---

## Running Tests

To run the integrated GoogleTest suite (Base64, Crypto, etc.):

```bash
cd build
ctest --output-on-failure
```
