#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include "crypto_library.hpp"

int main() {
    namespace lw2 = myCrypto::lab_second;
    namespace lw3 = myCrypto::lab_third;

    std::vector<ll> params = lw2::generateRSAParameters();
    std::string filename = "Ryan_Gosling.jpg";
    //ll s = lw3::signRSA(filename, params); // Подписываем файл

    std::string sign_filename = "signed_" + filename;
    
    //std::cout << "RSA SIGN:" << std::endl;
    //std::cout << filename << ": " << std::boolalpha << lw3::checkSignRSA(filename, params, s) << std::endl; // попробуем проверить исходный файл на "подписанность"
    //std::cout << sign_filename << ": " << std::boolalpha << lw3::checkSignRSA(sign_filename, params, s) << std::endl; // попробуем проверить подписанный файл на "подписанность"

    std::cout << "\nELGAMAL SIGN:" << std::endl;
    params = lw3::generateSignElgamalParameters();
    
    char *syms = new char[4]{'g', 'p', 'x', 'y'};
    std::for_each(params.begin(), params.end(), [syms](long long n) mutable { 
        std::cout << *syms << " = " << n << std::endl;
        syms++;
    });
    delete[] syms;
    
    std::pair<ll, ll> RSkeys = lw3::signElgamal(filename, params);
    
    
    return 0;
}