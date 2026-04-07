import sys

if len(sys.argv) != 3:
    print("Usage: python3 generate_network.py <n> <k>")
    print("Example: python3 generate_network.py 5 3")
    sys.exit(1)

n = int(sys.argv[1])
k = int(sys.argv[2])

if k > n:
    print("Error: Threshold (k) cannot be greater than total nodes (n).")
    sys.exit(1)

yaml = "services:\n"
yaml += "  setup_keys:\n"
yaml += "    build: .\n"
yaml += "    volumes:\n      - ./keys:/app/keys\n"
yaml += f'    command: ["./keygen", "{n}", "{k}", "/app/keys"]\n\n'

for i in range(1, n + 1):
    # Find peers for this node
    peers =[f'"http://node{j}:8080"' for j in range(1, n + 1) if j != i]
    peers_str = ", ".join(peers)
    
    # Map external ports starting from 8081
    external_port = 8080 + i
    
    yaml += f"  node{i}:\n"
    yaml += "    build: .\n"
    yaml += "    volumes:\n      - ./keys:/app/keys\n"
    yaml += "    depends_on:\n      setup_keys:\n        condition: service_completed_successfully\n"
    yaml += f'    command: ["./server_main", "8080", "{i}", "{k}", "/app/keys/node{i}.key", "/app/keys/coord.key", {peers_str}]\n'
    yaml += "    ports:\n"
    yaml += f'      - "{external_port}:8080"\n\n'

with open("docker-compose.yml", "w") as f:
    f.write(yaml)

print(f"[+] Successfully generated docker-compose.yml for a {k}-of-{n} network!")
print(f"[+] Nodes will be available on ports 8081 through {8080 + n}.")