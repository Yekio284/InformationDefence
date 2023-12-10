#include <iostream>
#include <vector>
#include <algorithm>
#include <fstream>
#include "crypto_library.hpp"

int main() {
    typedef myCrypto::RGR::Alice rgr_Alice;
    typedef myCrypto::RGR::Bob rgr_Bob;

    std::ifstream file("hamilton_files/hamilton_graph_info.txt");
    std::ifstream file_cycle("hamilton_files/hamilton_cycle.txt");
    
    // rgr_Graph graph(file, file_cycle);
    // std::cout << graph.getN() << ' ' << graph.getM() << std::endl;
    // graph.printHamiltonCycle();
    // graph.printEdges();
    // graph.printAdjacencyMatrix();
    
    rgr_Alice alice(file, file_cycle);
   
    //std::cout << std::boolalpha<< alice.match(alice.getAdjacencyMatrix(), alice.getAdjacencyMatrixH(), alice.getPermutation(), alice.Graph::getN());
    //std::cout << std::noboolalpha << std::endl;
   //
    //std::cout << "Permutation: ";
    //alice.printPermutation();
//
    //std::cout << "Hamilton cycle: ";
    //alice.printHamiltonCycle();
    //std::cout << std::endl;
    //
    //alice.printAdjacencyMatrix();
    //std::cout << std::endl << std::endl;
    //
    //alice.printAdjacencyMatrixH();

   // auto matrixF = alice.getAdjacencyMatrixF();

    rgr_Bob bob(alice.getAdjacencyMatrixF());

    return 0;
}