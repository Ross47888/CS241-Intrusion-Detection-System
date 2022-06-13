#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <pcap.h>
extern int globverbose;
extern unsigned long pcount;
void analyse(const struct pcap_pkthdr *header,
              const unsigned char *packet);

#endif
