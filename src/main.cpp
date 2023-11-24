#include <iostream>
#include "crypto_library.hpp"

typedef myCrypto::lab_fifth::Server lw5_Server;
typedef myCrypto::lab_fifth::Client lw5_Client;

int main() {
    lw5_Server server;

    std::cout << server.getC() << ' ' << server.getD() << ' ' << server.getN() << std::endl;

    return 0;
}