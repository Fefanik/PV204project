Client module plan

Goal:
- implement a C++ client CLI for document submission and timestamp verification

Planned commands:
- client_cli stamp <file> [server_url]
- client_cli verify <file> <receipt.json>

Current server contract:
- POST /timestamp
- request JSON: {"document_hash":"<hash>"}
- response JSON includes:
  - status
  - timestamp
  - payload_signed
  - final_signature_b64
  - public_key_b64