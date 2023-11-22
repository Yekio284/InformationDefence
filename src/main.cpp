#include <iostream>
#include <utility>
#include <limits>
#include "crypto_library.hpp"

#define DEBUGDECK 0

typedef myCrypto::lab_fourth::Game lw4_Game;
typedef myCrypto::lab_fourth::Player lw4_Player;

int main() {
    lw4_Game game;
    
    int n = 0;
    while (n < 2 || n > 23) {
        try {
            std::cout << "Enter num of players (2-23 or -1 to exit): ";
            std::cin >> n;
            if (std::cin.fail()) {
                std::cin.clear();
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                throw std::string("Incorrect input. Enter an integer number");
            }
            
            if (n == -1)
                return 0;
            else if (n < 2 || n > 23)
                throw std::string("Incorrect input."); 
        }
        catch (const std::string err) {
            std::cout << err << std::endl;
        }
        catch (const std::exception &err) {
            std::cout << "Something went wrong... " << err.what() << std::endl;
        }
    }

    std::vector<lw4_Player> players(n);
    std::generate(players.begin(), players.end(), [&game](){ return lw4_Player(game.getP()); });

    auto deck = game.generateDeck();

    #if DEBUGDECK
    short i = 1;
    std::for_each(deck.begin(), deck.end(), [&i](const std::pair<ll, std::string> p){
        std::cout << "i = " << i << "\tfirst = " << p.first << "\tsecond = " << p.second << std::endl;
        i++;
    });
    #endif

    short k = 0;
    std::vector<ll> numsOfDeck(52);
    std::for_each(deck.begin(), deck.end(), [&numsOfDeck, &k](const std::pair<ll, std::string> p){
        numsOfDeck[k] = p.first;
        k++;
    });

    std::for_each(players.begin(), players.end(), [&numsOfDeck, &game](lw4_Player player){
        player.encryptAndShuffleDeck(game.getP(), numsOfDeck);
    });

    return 0;
}