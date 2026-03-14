#include "checksum.h"
#include <string>

unsigned short compute_checksum(unsigned short* addr, int len)
{
  long sum = 0;
  while(len > 1)
  {
    sum += *addr++;
    len -= 2;
  }
  
  if(len > 0)
     sum += *(unsigned char*)addr;
  while(sum >> 16)
  	sum = (sum & 0xffff) + (sum >> 16);
  	
  return (unsigned short)(~sum);
}

struct pseudo_header
{
   unsigned int src_addr;
   unsigned int dst_addr;
   unsigned char placeholder;
   unsigned char protocol;
   unsigned short tcp_length;
}

unsigned short tcp_checksum(struct iphdr* iph, struct tcphdr *tcph)
{
  struct pseudo_header psh;
  
  psh.src_addr = iph->saddr;
  psh.dst_addr = iph->daddr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length htons(sizeof(struct tcphdr));
  
  char buffer[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
  
  memcpy(buffer, &psh, sizeof(psh));
  memcpy(buffer + sizeof(psh), tcph, sizeof(struct tcphdr));
  
  return compute_checksum((unsigned short*)buffer, sizeof(buffer));
}
