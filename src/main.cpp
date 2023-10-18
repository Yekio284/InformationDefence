#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include "crypto_library.hpp"

#define SHAMIR 0
#define ELGAMAL 1

#if SHAMIR

int main() {
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

#elif ELGAMAL

int main() {
    namespace lw2 = myCrypto::lab_second;
    
    std::string fileName = "lab.txt";
    std::string fileName2 = "Ryan_Gosling.jpg";
    std::string fileName3 = "KURSOVAYA.pdf";

    std::vector<ll> params = lw2::generateElgamalParameters();
    std::vector<ll> r_keys = lw2::encodeElgamal(fileName, params);
    lw2::decodeElgamal("encoded_lab.txt", params, r_keys);

    r_keys = lw2::encodeElgamal(fileName2, params);
    lw2::decodeElgamal("encoded_Ryan_Gosling.jpg", params, r_keys);

    r_keys = lw2::encodeElgamal(fileName3, params);
    lw2::decodeElgamal("encoded_KURSOVAYA.pdf", params, r_keys);

    return 0;
}

#endif