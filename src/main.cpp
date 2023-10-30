#include <iostream>
#include <string>
#include <vector>
#include "crypto_library.hpp"

int main () {
    namespace lw2 = myCrypto::lab_second;
    namespace lw3 = myCrypto::lab_third;

    std::vector<ll> params = lw2::generateRSAParameters();
    std::string filename = "Ryan_Gosling.jpg";
    ll s = lw3::signRSA(filename, params); // Подписываем файл

    std::string sign_filename = "signed_" + filename;
    
    std::cout << std::boolalpha << lw3::checkSignRSA(filename, params, s) << std::endl; // попробуем проверить исходный файл на "подписанность"
    std::cout << std::boolalpha << lw3::checkSignRSA(sign_filename, params, s) << std::endl; // попробуем проверить подписанный файл на "подписанность"

    return 0;
}