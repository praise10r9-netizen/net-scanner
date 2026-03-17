#ifndef SNIFFER_H
#define SNIFFER_H

#include <string>

class PacketSniffer
{
  public:
     void start_sniffing(std::string target_ip);
};

#endif
