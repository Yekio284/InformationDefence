#include <iostream>
#include <vector>
#include <algorithm>
#include <fstream>
#include "crypto_library.hpp"

int main() {
    typedef myCrypto::RGR::Graph rgr_Graph;

    std::ifstream file("hamilton_files/hamilton_graph_info.txt");
    std::ifstream file_cycle("hamilton_files/hamilton_cycle.txt");
    
    rgr_Graph graph(file, file_cycle);

    std::cout << graph.getN() << ' ' << graph.getM() << std::endl;
    graph.printHamiltonCycle();
    graph.printEdges();
    
    return 0;
}