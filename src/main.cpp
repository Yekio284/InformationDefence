#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include "crypto_library.hpp"

#define RSA 0
#define ELGAMAL 0
#define GOST 0
#define ALL 1
#define DEBUGPARAMS 0

#if RSA

int main() {
    namespace lw2 = myCrypto::lab_second;
    namespace lw3 = myCrypto::lab_third;

    const std::vector<ll> params = lw2::generateRSAParameters();
    const std::string filename = "Ryan_Gosling.jpg";
    const std::string sign_filename = "signed_" + filename;
    lw3::signRSA(filename, params);

    std::cout << "RSA SIGN:" << std::endl;

    #if DEBUGPARAMS
    char *param_names = new char[3]{'c', 'd', 'N'};
    std::for_each(params.begin(), params.end(), [param_names](long long n) mutable { 
        std::cout << *param_names << " = " << n << std::endl; 
        param_names++;
    });
    delete[] param_names;
    #endif

    std::cout << filename << ": " << std::boolalpha << lw3::checkSignRSA(filename, params) << std::endl;
    std::cout << sign_filename << ": " << lw3::checkSignRSA(sign_filename, params) << std::endl;

    return 0;
}

#endif

#if ELGAMAL

int main() {
    namespace lw3 = myCrypto::lab_third;

    const std::vector<ll> params = lw3::generateSignElgamalParameters();
    const std::string filename = "Ryan_Gosling.jpg";
    const std::string sign_filename = "signed_" + filename;
    lw3::signElgamal(filename, params);

    std::cout << "ELGAMAL SIGN:" << std::endl;

    #if DEBUGPARAMS
    char *param_names = new char[4]{'g', 'p', 'x', 'y'};
    std::for_each(params.begin(), params.end(), [param_names](long long n) mutable { 
        std::cout << *param_names << " = " << n << std::endl; 
        param_names++;
    });
    delete[] param_names;
    #endif

    std::cout << filename << ": " << std::boolalpha << lw3::checkSignElgamal(filename, params) << std::endl;
    std::cout << sign_filename << ": " << lw3::checkSignElgamal(sign_filename, params) << std::endl;

    return 0;
}

#endif

#if GOST

int main() {
    namespace lw3 = myCrypto::lab_third;

    const std::vector<ll> params = lw3::generateSignGOSTParameters();
    const std::string filename = "Ryan_Gosling.jpg";
    const std::string sign_filename = "signed_" + filename;
    lw3::signGOST(filename, params);

    std::cout << "GOST SIGN:" << std::endl;

    #if DEBUGPARAMS
    char *param_names = new char[5]{'p', 'q', 'a', 'x', 'y'};
    std::for_each(params.begin(), params.end(), [param_names](long long n) mutable { 
        std::cout << *param_names << " = " << n << std::endl; 
        param_names++;
    });
    delete[] param_names;
    #endif

    std::cout << filename << ": " << std::boolalpha << lw3::checkSignGOST(filename, params) << std::endl; // попробуем проверить исходный файл на "подписанность"
    std::cout << sign_filename << ": " << lw3::checkSignGOST(sign_filename, params) << std::endl;

    return 0;
}

#endif

#if ALL

int main() {
    namespace lw2 = myCrypto::lab_second;
    namespace lw3 = myCrypto::lab_third;

    // RSA
    std::vector<ll> params = lw2::generateRSAParameters();
    const std::string filename = "Ryan_Gosling.jpg";
    const std::string sign_filename = "signed_" + filename;
    lw3::signRSA(filename, params);

    std::cout << "RSA SIGN:" << std::endl;

    #if DEBUGPARAMS
    char *param_names = new char[3]{'c', 'd', 'N'};
    std::for_each(params.begin(), params.end(), [param_names](long long n) mutable { 
        std::cout << *param_names << " = " << n << std::endl; 
        param_names++;
    });
    delete[] param_names;
    #endif

    std::cout << filename << ": " << std::boolalpha << lw3::checkSignRSA(filename, params) << std::endl;
    std::cout << sign_filename << ": " << lw3::checkSignRSA(sign_filename, params) << std::endl;

    // ELGAMAL
    params = lw3::generateSignElgamalParameters();
    lw3::signElgamal(filename, params);

    std::cout << "\nELGAMAL SIGN:" << std::endl;

    #if DEBUGPARAMS
    param_names = new char[4]{'g', 'p', 'x', 'y'};
    std::for_each(params.begin(), params.end(), [param_names](long long n) mutable { 
        std::cout << *param_names << " = " << n << std::endl; 
        param_names++;
    });
    delete[] param_names;
    #endif

    std::cout << filename << ": " << std::boolalpha << lw3::checkSignElgamal(filename, params) << std::endl;
    std::cout << sign_filename << ": " << lw3::checkSignElgamal(sign_filename, params) << std::endl;

    //GOST
    params = lw3::generateSignGOSTParameters();
    lw3::signGOST(filename, params);

    std::cout << "\nGOST SIGN:" << std::endl;

    #if DEBUGPARAMS
    param_names = new char[5]{'p', 'q', 'a', 'x', 'y'};
    std::for_each(params.begin(), params.end(), [param_names](long long n) mutable { 
        std::cout << *param_names << " = " << n << std::endl; 
        param_names++;
    });
    delete[] param_names;
    #endif

    std::cout << filename << ": " << std::boolalpha << lw3::checkSignGOST(filename, params) << std::endl;
    std::cout << sign_filename << ": " << lw3::checkSignGOST(sign_filename, params) << std::endl;

    return 0;
}

#endif