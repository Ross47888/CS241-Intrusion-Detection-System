#include "sniff.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include "dispatch.h"

int globverbose;
pcap_t *pcap_handle;
unsigned long pcount = 0;

//when interrupt signal
//this frees up memory and ends program
void handler(int num){
  if(pcap_handle){pcap_close(pcap_handle);}
  if(arrayIP != NULL){free(arrayIP);}
  printf("\n%d SYN packets detected from %d different IPs (syn attack)",synSlip,uniqueIP);
  printf("\n%d ARP responses (cache poisoning)",arpAttack);
  printf("\n%d URL Blacklist violations\n",urlUse);
  exit(EXIT_SUCCESS);
}


// Application main sniffing loop
void sniff(char *interface, int verbose) {
  globverbose = verbose;
  // Open network interface for packet capture
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_handle = pcap_open_live(interface, 4096, 1, 0, errbuf);

  //network interface check
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }

  //To take interrutatic unsigned long pcount = 0;pt of ctrl & c
  struct sigaction sa;
  sa.sa_handler = handler;
  sigaction(SIGINT,&sa,NULL);

  // Capture packets
  pcap_loop(pcap_handle, 0, my_packet_handler, NULL);

}


void my_packet_handler(
    unsigned char *args,
    const struct pcap_pkthdr *packet_header,
    const unsigned char *packet)
{
  dispatch(packet_header, packet);
  pcount++;
}



//   // Capture packets (very ugly code)
//   struct pcap_pkthdr header;
//   const unsigned char *packet; = 0
//   while (1) {
//     packet = pcap_next(pcap_handle, &header);
//     if (packet == NULL) {
//       if (verbose) {
//         printf("No packet received. %s\n", pcap_geterr(pcap_handle));
//       }
//     } else {
//       if (verbose) {
//         dump(packet, header.len);
//       }
//       dispatch(&header, packet, verbose);
//     }
//   }
// }

// Utility/Debugging method for dumping raw packet data
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
//   pcount++;
//
