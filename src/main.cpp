#include <iostream>
#include <string>
#include <vector>
#include "crypto_library.hpp"

int main () {
    namespace lw2 = myCrypto::lab_second;
    namespace lw3 = myCrypto::lab_third;

    auto params = lw2::generateRSAParameters();
    std::string filename = "Ryan_Gosling.jpg";
    lw3::signRSA(filename, params);

    return 0;
}