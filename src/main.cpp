#include <iostream>
#include "crypto_library.hpp"

typedef myCrypto::lab_fourth::Game lw4_Game;
typedef myCrypto::lab_fourth::Player lw4_Player;

int main() {
    lw4_Game game;

    std::cout << "p = " << game.getP() << std::endl;
    game.printDesk();
    game.shuffleDesk();
    game.printDesk();
    game.shuffleDesk();
    game.printDesk();
    std::cout << "p = " << game.getP() << std::endl;

    lw4_Player player1(game.getP());
    lw4_Player player2(game.getP());

    return 0;
}