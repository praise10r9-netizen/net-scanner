#include <iostream>
#include "scanner.h"

int main(int argc, char* argv[])
{
   if(argc < 3)
   {
     std::cout << "Usage: ./netscan <target_ip> <port>\n";
     return 1;
   }
   
   std::string target = argv[1];
   int port = atoi(argv[2]);
   
   Scanner scanner(target);
   scanner.syn_scan(port);
   
   return 0;
}
