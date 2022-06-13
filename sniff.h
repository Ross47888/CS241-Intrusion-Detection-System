#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H
#include <pcap.h>
#include <signal.h>

extern unsigned int synSlip;
extern unsigned int arpAttack;
extern unsigned int urlUse;
extern unsigned int uniqueIP;
extern char **arrayIP;

void sniff(char *interface, int verbose);
void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header,
    const u_char *packet);

// void dump(const unsigned char *data, int length);

#endif


// enp11s0: inet 192.168.8.120
