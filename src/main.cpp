#include <iostream>
#include <vector>
#include <algorithm>
#include "crypto_library.hpp"

typedef myCrypto::lab_fifth::Server lw5_Server;
typedef myCrypto::lab_fifth::Client lw5_Client;

int main() {
    namespace lw1 = myCrypto::lab_first;
    namespace lw3 = myCrypto::lab_third;

    lw5_Server server;

    //std::cout << server.getC() << ' ' << server.getD() << ' ' << server.getN() << std::endl;

    std::vector<lw5_Client> votersVec(6);
    std::for_each(votersVec.begin(), votersVec.end(), [&server](lw5_Client client){ 
        client.generate_n(server.getAddress(), lw1::random(0, 2)); 
        client.generate_r(server.getN());
    });

    return 0;
}