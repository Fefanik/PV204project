#include "keygen.hpp"
#include <iostream>
#include <exception>

int main(int argc, char* argv[]) {
    try {
        const KeygenConfig config = parse_arguments(argc, argv);
        run_keygen(config);
    } catch (const std::invalid_argument& e) {
        std::cerr << "ERROR: Invalid arguments.\n" << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) { // Catch broader exceptions too
        std::cerr << "ERROR: An exception occurred.\n" << e.what() << std::endl;
        return 2;
    }
    return 0;
}