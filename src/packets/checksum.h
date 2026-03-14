#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <netinet/ip.h>
#include <netinet/tcp.h>

unsigned short compute_checksum(unsigned short *addr, int len);

unsigned short tcp_checksum(struct iphdr *iph, struct tcphdr *tcph);

#endif
