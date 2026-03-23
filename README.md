# PV204project
Trusted timestamping server with threshold signing key

## Client module

Current status
- C++ client CLI integrated into the project build
- `stamp` is functional end-to-end
- `verify` is functional end-to-end

Commands
- `./build/client_cli stamp <file> [server_url]`
- `./build/client_cli verify <file> <receipt.json>`

Default server URL
- `http://localhost:8081`

How to test locally

1. Start the backend:
   `docker compose up --build`

2. Build locally:
   `cmake -S . -B build -G Ninja && cmake --build build`

3. Create a test file:
   `echo 'hello timestamp project' > test.txt`