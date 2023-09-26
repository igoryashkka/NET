#ifndef MY_HEADER_H_NET
#define MY_HEADER_H_NET


#define ETHERNET_HEADER_LENGTH 14
#include <time.h>

#include <stdlib.h>

#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <pthread.h>




struct Packet_stat {
    struct pcap_pkthdr *generic_packet_information;
    struct ethhdr *eth_header;
    struct ip *ip_header;
    int totalPackets;
    int totalPayloadSize;
};
 
void packet_callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void capture_packets(pcap_t *handle, const char *filter_exp);
//void print_net();

#endif // MY_HEADER_H_NET