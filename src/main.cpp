#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include "crypto_library.hpp"

#define SHAMIR 1

#if SHAMIR

int main() {
    namespace lw1 = myCrypto::lab_first;
    namespace lw2 = myCrypto::lab_second;
    
    std::string fileName = "lab.txt";
    std::string fileName2 = "Ryan_Gosling.jpg";
    std::string fileName3 = "KURSOVAYA.pdf";

    std::vector<ll> params = lw2::generateShamirParameters();
    lw2::encodeShamir(fileName, params);
    lw2::decodeShamir("encoded_lab.txt", params);

    lw2::encodeShamir(fileName2, params);
    lw2::decodeShamir("encoded_Ryan_Gosling.jpg", params);

    lw2::encodeShamir(fileName3, params);
    lw2::decodeShamir("encoded_KURSOVAYA.pdf", params);

    return 0;
}

#endif