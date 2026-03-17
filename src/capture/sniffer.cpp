#include "sniffer.h"

#include <pcap.h>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string>

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  struct iphdr* iph = (struct iphdr*) (packet + 14);
  struct tcphdr *tcph = (struct tcphdr*)(packet + 14 + iph->ihl * 4);
  
  if(tcph->syn && tcph->ack)
     std::cout << "Port OPEN\n";
     
  else if(tcph->rst)
     std::cout << "Port CLOSED\n";
}

void PacketSniffer::start_sniffing(std::string target_ip)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  
  pcap_t *handle = pcap_open_live("eth0",65535, 1, 1000, errbuf);
  
  if(handle == NULL)
  {
     std::cerr << "pcap error: " << errbuf << "\n";
     return;
  }
  
  pcap_loop(handle, 10,packet_handler,NULL);
  
  pcap_close(handle);
}
