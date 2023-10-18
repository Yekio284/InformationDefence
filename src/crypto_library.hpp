#pragma once

#include <vector>
#include <fstream>

typedef long long ll;

namespace myCrypto {
    namespace lab_first { 
        __int128_t powMod(__int128_t a, __int128_t x, __int128_t p); // a^x mod p
        ll binPow(ll a, ll x); // a^x
        std::vector<ll> extendedGCD(ll a, ll b); // Обобщённый алгоритм Евклида
        bool isPrime(ll n);
        ll random(ll a, ll b);
        ll generatePrime();
        ll generateCommonKey(); // Функция построения общего ключа для двух абонентов по схеме Диффи-Хеллмана
        ll discreteLogarithm(ll a, ll p, ll y); // a^x mod p = y. Нужно найти x. Метод Шенкса
    }
    namespace lab_second {
        ll gcd(ll a, ll b);
        
        std::vector<ll> generateShamirParameters(); // функция генерации cA, dA, cB, dB, p
        void encodeShamir(const std::string &inputFileName, const std::vector<ll> &params);
        void decodeShamir(const std::string &encodedFileName, const std::vector<ll> &params);
        
        std::vector<ll> generateElgamalParameters(); // функция генерации cA, dA, cB, dB, p, g
        std::vector<ll> encodeElgamal(const std::string &inputFileName, const std::vector<ll> &params);
        void decodeElgamal(const std::string &encodedFileName, const std::vector<ll> &params, const std::vector<ll> &R_keys);

        std::vector<__int128_t> generateRSAParameters(); // функция генерации cA, dA, nA, cB, dB, nB
        void encodeRSA(const std::string &inputFileName, const std::vector<__int128_t> &params);
        void decodeRSA(const std::string &encodedFileName, const std::vector<__int128_t> &params);

        std::string encodeVernam(const std::string &inputFileName);
        void decodeVernam(const std::string &encodedFileName, const std::string &key);
    }
}