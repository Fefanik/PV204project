#include <iostream>
#include <string>

static void print_usage() {
    std::cout
        << "Usage:\n"
        << "  client_cli stamp <file> [server_url]\n"
        << "  client_cli verify <file> <receipt.json>\n";
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_usage();
        return 1;
    }

    const std::string command = argv[1];

    if (command == "stamp") {
        const std::string file = argv[2];
        const std::string server_url = (argc >= 4) ? argv[3] : "http://localhost:8081";
        std::cout << "STAMP not implemented yet\n";
        std::cout << "file=" << file << "\n";
        std::cout << "server_url=" << server_url << "\n";
        return 0;
    }

    if (command == "verify") {
        if (argc < 4) {
            print_usage();
            return 1;
        }
        const std::string file = argv[2];
        const std::string receipt = argv[3];
        std::cout << "VERIFY not implemented yet\n";
        std::cout << "file=" << file << "\n";
        std::cout << "receipt=" << receipt << "\n";
        return 0;
    }

    print_usage();
    return 1;
}