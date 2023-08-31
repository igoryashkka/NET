#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <stdlib.h>
/// @brief 
volatile sig_atomic_t stop = 0; // A flag to indicate if capturing should stop
#define ETH_BYTES 14
//////
/// Sniffing ip-packets , filtes : icmp , udp
/// Add another way to represent data 
/// Add more useful infrom in process_packet func
/// Handle start|stop run and choose filter in run-time
//////
///Need to add help note
//////

#define ETHERNET_HEADER_LENGTH 14

struct Packet_stat {
    struct pcap_pkthdr *generic_packet_information;
    struct ethhdr *eth_header;
    struct ip *ip_header;
    int totalPackets;
    int totalPayloadSize;
};



void process_packet(const u_char *packet,const struct pcap_pkthdr *pkthdr,struct Packet_stat **packet_info);



void print_packet_info(struct Packet_stat* packet_info);
void capture_packets(pcap_t *handle, const char *filter_exp);

void packet_callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct Packet_stat *packet_info;

    process_packet(packet,pkthdr,&packet_info);
    print_packet_info(packet_info);
    free(packet_info->generic_packet_information);
    free(packet_info->eth_header);
    free(packet_info->ip_header);
    free(packet_info);
}






void process_packet(const u_char *packet,const struct pcap_pkthdr *pkthdr, struct Packet_stat **packet_info) {

    *packet_info = malloc(sizeof(struct Packet_stat));
    (*packet_info)->generic_packet_information = malloc(sizeof(struct pcap_pkthdr));
    (*packet_info)->eth_header = malloc(sizeof(struct ethhdr));
    (*packet_info)->ip_header = malloc(sizeof(struct ip));

    *(*packet_info)->generic_packet_information = *pkthdr;
    memcpy((*packet_info)->eth_header, packet, sizeof(struct ethhdr));
    memcpy((*packet_info)->ip_header, packet + ETHERNET_HEADER_LENGTH, sizeof(struct ip));

    //(*packet_info)->eth_header = (struct ethhdr *)packet;
    //(*packet_info)->ip_header = (struct ip *)(packet + ETH_BYTES);
}



void print_packet_info(struct Packet_stat* packet_info){
    static unsigned int index_packet = 0; 
    //Print generic info 
    //here run-time error
    printf("[%d] TS:%ld ",index_packet, (*packet_info).generic_packet_information->ts.tv_sec);
    printf("len:%d \n",(*packet_info).generic_packet_information->len);

    
    //Print MAC adresess 
    printf("Source MAC: %02X:%02X:%02X:%02X:%02X:%02X | Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           packet_info->eth_header->h_source[0], packet_info->eth_header->h_source[1], packet_info->eth_header->h_source[2],
           packet_info->eth_header->h_source[3], packet_info->eth_header->h_source[4], packet_info->eth_header->h_source[5],
           packet_info->eth_header->h_dest[0], packet_info->eth_header->h_dest[1], packet_info->eth_header->h_dest[2],
           packet_info->eth_header->h_dest[3], packet_info->eth_header->h_dest[4], packet_info->eth_header->h_dest[5]);
    

    // Copy the source and destination IP addresses
    struct in_addr src_addr = packet_info->ip_header->ip_src;
    struct in_addr dst_addr = packet_info->ip_header->ip_dst;

    // Convert the copied addresses to strings
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &src_addr, src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst_addr, dst_ip_str, INET_ADDRSTRLEN);


    printf("Source IP: %s | Destination IP: %s | Protocol: %d\n",
           src_ip_str, dst_ip_str, packet_info->ip_header->ip_p);
  
   
    printf("\n\n");
    
   index_packet++;
}







int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *dev;
    pcap_t *handle;
    int option;
    int icmp_mode = 0;
    int udp_mode = 0;
    int run_mode = 0;

    // Parse command-line arguments
    while ((option = getopt(argc, argv, "iur")) != -1) {
        switch (option) {
            case 'i':
                icmp_mode = 1;
                break;
            case 'u':
                udp_mode = 1;
                break;
            case 'r':
                run_mode = 1;
                break;
            default:
                fprintf(stderr, "Usage: %s -i -u -r\n", argv[0]);
                return 1;
        }
    }

   
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error finding devices: %s\n", errbuf);
        return 1;
    }

    
    dev = alldevs;

    
    handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Could not open device %s: %s\n", dev->name, errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }

    printf("Running custom code...\n");

    if (icmp_mode) {
        capture_packets(handle, "icmp");
    } else if (udp_mode) {
        capture_packets(handle, "udp");
    } else if (run_mode) {
        capture_packets(handle, NULL); 
    } else {
        printf("Usage: %s -i -u -r\n", argv[0]);
    }


    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}


void capture_packets(pcap_t *handle, const char *filter_exp) {
    struct bpf_program fp;
    
    // Compile filter expression
    if (filter_exp && pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return;
    }
    
    // Set compiled filter
    if (filter_exp && pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return;
    }

    
    const char *capture_msg = filter_exp ? filter_exp : "ALL";
    printf("Press 's' to stop sniffing %s packets...\n", capture_msg);

    
    pcap_loop(handle, 0, packet_callback, NULL);
}


// ______________________________
