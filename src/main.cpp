#include <iostream>
#include <utility>
#include <limits>
#include <algorithm>
#include <vector>
#include <map>
#include <fstream>
#include <ctime>
#include <iomanip>
#include "crypto_library.hpp"

typedef myCrypto::lab_fourth::Game lw4_Game;
typedef myCrypto::lab_fourth::Player lw4_Player;

std::string currentDateTime() { // Узнаём текущую дату и врему
    std::time_t t = std::time(nullptr);
    std::tm* now = std::localtime(&t);
 
    char buffer[128];
    strftime(buffer, sizeof(buffer), "%m-%d-%Y %X", now);
    
    return buffer;
}

int main() {
    lw4_Game game;
    std::ofstream logging("log.txt");

    int n = 0; // Кол-во игроков
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
    
    logging << "Game time: " << currentDateTime() << std::endl << "Number of players: " << n << std::endl << std::endl; // Логируем дату и время
    logging << "Generated \"p\": " << game.getP() << std::endl; // Логируем "p"

    std::vector<lw4_Player> players(n);
    std::generate(players.begin(), players.end(), [&game](){ return lw4_Player(game.getP()); }); // Генерируем массив игроков

    auto deck = game.generateDeck(); // Генерируем игральную колоду, где каждому уникальному номеру (ключу) соответствует уникальная карта

    logging << "\nGenerated deck:" << std::endl;                                            //
    std::for_each(deck.begin(), deck.end(), [&logging](const std::pair<ll, std::string> p){ // Логируем колоду
        logging << "num = "  << p.first << "\tstring = " << p.second << std::endl;          //
    });                                                                                     //

    short k = 0;                                                                                     //
    std::vector<ll> decimalCards(52);                                                                //
    std::for_each(deck.begin(), deck.end(), [&decimalCards, &k](const std::pair<ll, std::string> p){ // Переписываем уникальные ключи deck 
        decimalCards[k] = p.first;                                                                   // в отдельный вектор
        k++;                                                                                         //
    });                                                                                              //

    std::vector<ll> cardsToPutOnTable(5);
    std::copy(decimalCards.begin() + 2 * n, decimalCards.begin() + 2 * n + 5, cardsToPutOnTable.begin());
    decimalCards.erase(decimalCards.begin() + 2 * n, decimalCards.begin() + 2 * n + 5);

    logging << "\nWrote deck's keys to decimalCards vector" << std::endl << std::endl; // Логируем инфу о том, что создали вектор decimalCards

    std::for_each(players.begin(), players.end(), [&decimalCards, &game](lw4_Player player){  //
        player.encryptAndShuffleDeck(game.getP(), decimalCards);                              // Шифруем и перемешиваем карты
    });                                                                                       //

    logging << "Encrypted cards:" << std::endl;                                  //
    std::for_each(decimalCards.begin(), decimalCards.end(), [&logging](ll card){ // Логируем зашифрованные карты
        logging << card << std::endl;                                            //
    });                                                                          //

    game.giveEncryptedCardsToPlayers(decimalCards, players); // Выдаём зашифрованные карты игрокам
    
    logging << "\nGave encrypted cards to players" << std::endl << std::endl; // Логируем инфу о том, что выдали зашифрованные карты

    for (short j = 0; j < players.size(); j++)                        // Каждый игрок расшифровывает свои карты 
        players[j].decryptAndSetCards(players, deck, game.getP(), j); //
    
    logging << "Players decrypted their cards" << std::endl << std::endl; // Логируем инфу о том, что игроки расшифровали свои карты

    std::cout << "Cards on a table: ";
    std::for_each(cardsToPutOnTable.begin(), cardsToPutOnTable.end(), [&deck](ll n){
        std::cout << deck[n] << ' ';
    });
    std::cout << std::endl;

    std::for_each (players.begin(), players.end(), [](lw4_Player player){ //
        player.showCards();                                               // Каждый игрок показывает свои карты
    });                                                                   //
    
    k = 1;                                                                                               //
    logging << "Player's C/D keys:" << std::endl;                                                        //
    std::for_each(players.begin(), players.end(), [&k, &logging](lw4_Player player){                     // Логируем инфу о C, D ключах игроков 
        logging << "Player " << k << ": C = " << player.getC() << " D = " << player.getD() << std::endl; //
        k++;                                                                                             //
    });                                                                                                  //

    logging.close();

    return 0;
}