#include <iostream>
#include <vector>
#include <algorithm>
#include "crypto_library.hpp"

typedef myCrypto::lab_fifth::Server lw5_Server;
typedef myCrypto::lab_fifth::Client lw5_Client;

int main() {
    namespace lw1 = myCrypto::lab_first;
    namespace lw3 = myCrypto::lab_third;

    std::remove("database.csv");

    lw5_Server server;

    std::vector<lw5_Client> votersVec(10);
    for (auto &client : votersVec) {
        client.setVote(lw1::random(0, 2)); // 0 - нет, 1 - да, 2 - воздержался
        client.generate_n(server.getAddress()); 
        client.generate_r(server.getN());
        client.generate_h(server.getN());
        client.compute_h1(server.getD(), server.getN());
        
        ll s1 = server.addVoterAndComputeS1(client.getId(), client.getH1());
        if (s1 == -1) {
            std::cout << "id: " << client.getId() << " Already in vote." << std::endl;
            continue;
        }

        client.setS1(s1);
        client.compute_s(server.getN());
        
        if (server.recieveBulletinAndAddToDB(client.getN(), client.getS(), client.getId()))
            std::cout << "id<" << client.getId() << ">: good" << std::endl; 
        else
            std::cout << "id<" << client.getId() << ">: bad" << std::endl;  
    }

    // попытка поучаствовать еще раз для votersVec[7];
    votersVec[7].setVote(lw1::random(0, 2)); // 0 - нет, 1 - да, 2 - воздержался
    votersVec[7].generate_n(server.getAddress()); 
    votersVec[7].generate_r(server.getN());
    votersVec[7].generate_h(server.getN());
    votersVec[7].compute_h1(server.getD(), server.getN());
    
    ll s1 = server.addVoterAndComputeS1(votersVec[7].getId(), votersVec[7].getH1());
    if (s1 == -1)
        std::cout << "id<" << votersVec[7].getId() << "> Already in vote." << std::endl;

    return 0;
}