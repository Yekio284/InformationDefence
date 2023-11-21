#pragma once

#include <vector>
#include <string>
#include <fstream>
#include <map>

typedef long long ll;

namespace myCrypto {
    namespace lab_first { 
        ll powMod(__int128_t a, __int128_t x, __int128_t p); // a^x mod p
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

        std::vector<ll> generateRSAParameters(); // функция генерации cB, dB, nB
        void encodeRSA(const std::string &inputFileName, const std::vector<ll> &params);
        void decodeRSA(const std::string &encodedFileName, const std::vector<ll> &params);

        std::string encodeVernam(const std::string &inputFileName);
        void decodeVernam(const std::string &encodedFileName, const std::string &key);
    }
    namespace lab_third {
        std::string computeHashFromFile(std::ifstream &file);
        ll hexToDecimal(const std::string &hex_str); // str -> ll
        ll generateBigPrime();

        void signRSA(const std::string &inputFileName, const std::vector<ll> &params);
        bool checkSignRSA(const std::string &fileNameToCheck, const std::vector<ll> &params);

        std::vector<ll> generateSignElgamalParameters(); // g, p, x, y
        void signElgamal(const std::string &inputFileName, const std::vector<ll> &params);
        bool checkSignElgamal(const std::string &fileNameToCheck, const std::vector<ll> &params);

        std::vector<ll> generateSignGOSTParameters(); // p, q, a, x, y
        void signGOST(const std::string &inputFileName, const std::vector<ll> &params);
        bool checkSignGOST(const std::string &fileNameToCheck, const std::vector<ll> &params);
    }
    namespace lab_fourth {
        class Game {
        private:
            const std::vector<std::string> cardName = {"2", "3", "4", "5", "6", "7", 
                                                       "8", "9", "10", "J", "Q", "K", "A"};
            const std::vector<std::string> suits = {"♤", "♡", "♧", "♢"};
            std::vector<std::string> fullCardNames;
            ll p; // Безопасное простое число

        public:
            Game();

            void shuffleDesk();
            void printFullCardNames() const;
            ll getP() const;
            std::vector<std::string> getFullCardNames() const;
            std::map<ll, std::string> generateDeck() const;

            ~Game();
        };
        
        class Player {
        private:
            ll c, d;

        public:
            Player();
            Player(const ll &p);

            void encryptAndShuffleDeck(const ll &p, std::vector<ll> &nums) const;

            ~Player();
        };
    }
}