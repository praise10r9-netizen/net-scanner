#include "syn_scan.h"

#include <iostream>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

SynScanner::SynScanner(std::string ip)
{
  target_ip = ip;
}

void SynScanner::scan(int port)
{
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  
  if(sock < 0)
  {
    perror("socket");
    return;
  }
  
  char packet[4096];
  memset(packet,0,4096);
  
  struct iphdr *iph = (struct iphdr*)packet;
  struct tcphdr *tcph = (struct tcphdr*) (packet + sizeof(struct iphdr));
  
  iph->ihl = 5;
  iph->version = 4;
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
  iph->protocol = IPPROTO_TCP;
  iph->check = compute_checksum((unsigned short*)iph, sizeof(struct iphdr));
  
  iph->saddr = inet_addr("192.168.1.100");
  iph->daddr = inet_addr(target_ip.c_str());
  
  tcph->source = htons(12345);
  tcph->dest = htons(port);
  tcph->seq = random();
  tcph->syn = 1;
  tcph->check = tcp_checksum(iph,tcph);
  tcph->window = htons(65535);
  
  sockaddr_in dest;
  dest.sin_family = AF_INET;
  dest.sin_port = htons(port);
  dest.sin_addr.s_addr = iph->daddr;
  
  sendto(sock, packet, iph->tot_len, 0,(sockaddr*)&dest, sizeof(dest));
  
  std::cout << "SYN sent to " << target_ip << ":" << port << "\n";
  
  close(sock);
}
