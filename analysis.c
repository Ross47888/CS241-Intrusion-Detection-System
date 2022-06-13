#include "analysis.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

unsigned int synSlip = 0;
unsigned int arpAttack = 0;
unsigned int urlUse = 0;
unsigned int uniqueIP = 0;
char **arrayIP;


//nts for array when uniqueIP 0, malloc
//else realloc


void analyse(const struct pcap_pkthdr *header,
             const unsigned char *packet) {
  // TODO your part 2 code here
  struct ether_header *eth_head = (struct ether_header *) packet;


  //detecting for arp attacks
  if(ntohs(eth_head->ether_type) == ETHERTYPE_ARP){
    const unsigned char * eth_packet = packet + ETH_HLEN;
    struct ether_arp *arp_packet = (struct ether_arp * ) eth_packet;
    struct arphdr *arp_head = (struct arphdr *) &arp_packet->ea_hdr;
    if(ntohs(arp_head->ar_op) == ARPOP_REPLY){
      arpAttack++;}
  }
  //detecting blacklist and SYN
  else if(ntohs(eth_head->ether_type) == ETHERTYPE_IP){
    const unsigned char * eth_packet = packet + ETH_HLEN;
    struct iphdr *ip_head = (struct iphdr *) eth_packet;
    const unsigned char *ip_packet = eth_packet + 4*ip_head->ihl;

    struct tcphdr *tcp_head = (struct tcphdr *) ip_packet;


    //synPacket
    //check source addresses to find uniqueIP
    if(tcp_head->syn){

      synSlip++;
      char macSaddr[18];

      snprintf(macSaddr, sizeof(macSaddr), "%02x:%02x:%02x:%02x:%02x:%02x",
         eth_head->ether_shost[0], eth_head->ether_shost[1],
         eth_head->ether_shost[2], eth_head->ether_shost[3],
         eth_head->ether_shost[4], eth_head->ether_shost[5]);

      if(uniqueIP == 0){
        arrayIP = malloc(sizeof(unsigned char *));
        arrayIP[0] = malloc(18*sizeof(unsigned char));
        strcpy(arrayIP[0], macSaddr);
        uniqueIP++;
      } else {
        int z=0;
        while(z <= uniqueIP){
          if(strcmp(macSaddr,arrayIP[z]) == 0){ //iq non unique
            z = uniqueIP+1; //exits while loop
          } else if (strcmp(macSaddr,arrayIP[z]) != 0){
            if(z == uniqueIP){ //total array scanned, still not equal
              arrayIP = realloc(arrayIP,(uniqueIP+1)*sizeof(unsigned char *));
              arrayIP[uniqueIP] = malloc(18*sizeof(unsigned char));
              strcpy(arrayIP[uniqueIP], macSaddr);
              uniqueIP++;
            }

            z++;
          }
        }
      }
    }
    //https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers

    //blacklist
    const char *apacket = (char *) (ip_packet + 4*tcp_head->doff);
    if (ntohs(tcp_head->dest) == 80 && strstr(apacket,"Host: www.google.co.uk")){
        urlUse++;
      }

    }
    if(globverbose){
        unsigned int i;
        // Decode Packet Header=
        printf("\n\n === PACKET %ld HEADER ===", pcount);
        printf("\nSource MAC: ");
        for (i = 0; i < 6; ++i) {
          printf("%02x", eth_head->ether_shost[i]);
          if (i < 5) {
            printf(":");
          }
        }
        printf("\nDestination MAC: ");
        for (i = 0; i < 6; ++i) {
          printf("%02x", eth_head->ether_dhost[i]);
          if (i < 5) {
            printf(":");
          }
        }
        printf("\nType: %hu\n", eth_head->ether_type);

    }

  }






// // Utility/Debugging method for dumping raw packet data
// void dump(const unsigned char *data, int length) {
//   unsigned int i;
//   static unsigned long pcount = 0;
//   // Decode Packet Header
//   struct ether_header *eth_header = (struct ether_header *) data;
//   printf("\n\n === PACKET %ld HEADER ===", pcount);
//   printf("\nSource MAC: ");
//   for (i = 0; i < 6; ++i) {
//     printf("%02x", eth_header->ether_shost[i]);
//     if (i < 5) {
//       printf(":");
//     }
//   }
//   printf("\nDestination MAC: ");
//   for (i = 0; i < 6; ++i) {
//     printf("%02x", eth_header->ether_dhost[i]);
//     if (i < 5) {
//       printf(":");
//     }
//   }
//   printf("\nType: %hu\n", eth_header->ether_type);
//   printf(" === PACKET %ld DATA == \n", pcount);
//   // Decode Packet Data (Skipping over the header)
//   int data_bytes = length - ETH_HLEN;
//   const unsigned char *payload = data + ETH_HLEN;
//   const static int output_sz = 20; // Output this many bytes at a time
//   while (data_bytes > 0) {
//     int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
//     // Print data in raw hexadecimal form
//
//     for (i = 0; i < output_sz; ++i) {
//       if (i < output_bytes) {
//         printf("%02x ", payload[i]);
//       } else {
//         printf ("   "); // Maintain padding for partial lines
//       }
//     }
//     printf ("| ");
//     // Print data in ascii form
//     for (i = 0; i < output_bytes; ++i) {
//       char byte = payload[i];
//       if (byte > 31 && byte < 127) {
//         // Byte is in printable ascii range
//         printf("%c", byte);
//       } else {
//         printf(".");
//       }
//     }
//     printf("\n");
//     payload += output_bytes;
//     data_bytes -= output_bytes;
//   }
// }
