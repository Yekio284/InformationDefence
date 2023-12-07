#pragma once

#include <vector>
#include <string>
#include <fstream>
#include <utility>
#include <map>
#include "../external/ap/ap.hpp"

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
    namespace lab_third { // Недостаток лабы в том, что после генерации хэш'а, он обрезается
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
        class Player;
        
        class Game {
        private:
            const std::vector<std::string> cardName = {"2", "3", "4", "5", "6", "7", 
                                                       "8", "9", "10", "J", "Q", "K", "A"};
            const std::vector<std::string> suits = {"♤", "♡", "♧", "♢"};
            std::vector<std::string> fullCardNames;
            ll p; // Безопасное простое число

        public:
            Game();

            ll getP() const;
            std::map<ll, std::string> generateDeck() const;
            void giveEncryptedCardsToPlayers(const std::vector<ll> &cards, 
                                             std::vector<myCrypto::lab_fourth::Player> &players) const;

            ~Game();
        };
        
        class Player {
        private:
            ll c, d;
            std::pair<ll, ll> encryptedCards;
            std::pair<std::string, std::string> decryptedCards;

        public:
            Player();
            explicit Player(const ll &p);

            void encryptAndShuffleDeck(const ll &p, std::vector<ll> &nums) const;
            void setEncryptedCards(const std::pair<ll, ll> encryptedCards);
            
            ll getLeftEncryptedCard() const;
            ll getRightEncryptedCard() const;
            ll getC() const;
            ll getD() const;
            
            void decryptAndSetCards(const std::vector<myCrypto::lab_fourth::Player> &players, 
                                    std::map<ll, std::string> &deck, const ll &p, const short i);
            void showCards() const;

            ~Player();
        };
    }
    namespace lab_fifth {
        class Server {
        private:
            ll c, d, n; // c - секретный ключ; d, n - открытые
            ll address;
            std::vector<ll> voters;

        public:
            Server();

            ll addVoterAndComputeS1(const ll &id, const ll &h1);
            
            bool recieveBulletinAndAddToDB(const ll &n, const ll &s, const ll &id) const;

            ll getC() const;
            ll getD() const;
            ll getN() const;
            ll getAddress() const;

            ~Server();
        };

        class Client {
        private:
            static inline ll count;
            ll rnd, n, r;
            ll id;
            ll h1, s1, s;
            char vote;
            ap_uint<256> h;
            
        public:
            Client();
            
            void setVote(const char vote);
            void setS1(const ll &s1);

            void generate_n(const ll &address);
            void generate_r(const ll &n);
            void generate_h(const ll &n);
            void compute_h1(const ll &d, const ll &n);
            void compute_s(const ll &n);

            ll getN() const;
            ll getR() const;
            ll getId() const;
            ll getH1() const;
            ll getS() const;
            char getVote() const;

            ~Client();
        };
    }
    namespace RGR { // Вариант 2: "Протокол доказательства с нулевым знанием для задачи «Гамильтонов цикл»"
        class Graph {
        private:
            ll n, m;
            std::vector<ll> hamilton_cycle; // Гамильтонов цикл
            std::vector<std::vector<bool>> adjacency_matrix; // Матрица смежности

        public:
            Graph();
            Graph(std::ifstream &fileInfo, std::ifstream &cycle);

            void printHamiltonCycle();

            ll getN() const;
            ll getM() const;

            ~Graph();
        };
    }
}