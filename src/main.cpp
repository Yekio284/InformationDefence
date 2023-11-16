#include <iostream>
#include "crypto_library.hpp"

typedef myCrypto::lab_fourth::Game lw4_Game;

int main() {
    lw4_Game game;

    game.printDesk();
    game.shuffleDesk();
    game.printDesk();
    game.shuffleDesk();
    game.printDesk();

    return 0;
}