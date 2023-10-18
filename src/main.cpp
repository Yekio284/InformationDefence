#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include "crypto_library.hpp"

#define SHAMIR 0
#define ELGAMAL 0
#define RSA 0
#define VERNAM 1

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

#elif RSA

int main() {
    namespace lw2 = myCrypto::lab_second;
    
    std::string fileName = "lab.txt";
    std::string fileName2 = "Ryan_Gosling.jpg";
    std::string fileName3 = "KURSOVAYA.pdf";

    std::vector<__int128_t> params = lw2::generateRSAParameters();
    lw2::encodeRSA(fileName, params);
    lw2::decodeRSA("encoded_lab.txt", params);

    lw2::encodeRSA(fileName2, params);
    lw2::decodeRSA("encoded_Ryan_Gosling.jpg", params);

    lw2::encodeRSA(fileName3, params);
    lw2::decodeRSA("encoded_KURSOVAYA.pdf", params);

    return 0;
}

#elif VERNAM

int main() {
    namespace lw2 = myCrypto::lab_second;
    
    std::string fileName = "lab.txt";
    std::string fileName2 = "Ryan_Gosling.jpg";
    std::string fileName3 = "KURSOVAYA.pdf";

    std::string key = lw2::encodeVernam(fileName);
    lw2::decodeVernam("encoded_lab.txt", key);

    key = lw2::encodeVernam(fileName2);
    lw2::decodeVernam("encoded_Ryan_Gosling.jpg", key);

    key = lw2::encodeVernam(fileName3);
    lw2::decodeVernam("encoded_KURSOVAYA.pdf", key);

    return 0;
}

#endif