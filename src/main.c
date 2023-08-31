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

#define ETHERNET_HEADER_SIZE 14

struct Packet_stat {
    struct pcap_pkthdr *generic_packet_information;
    struct ethhdr *eth_header;
    struct ip *ip_header;
    int totalPackets;
    int totalPayloadSize;
};


\
void process_packet(const u_char *packet,const struct pcap_pkthdr *pkthdr,struct Packet_stat **packet_info);



void print_packet_info(struct Packet_stat* packet_info);
void icmp_packet_callback(pcap_t *handle); // -i
void udp_packet_callback(pcap_t *handle); // -u
void run_mode_packet_callback(pcap_t *handle);// -r 


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
    memcpy((*packet_info)->ip_header, packet + ETHERNET_HEADER_SIZE, sizeof(struct ip));

    //(*packet_info)->eth_header = (struct ethhdr *)packet;
    //(*packet_info)->ip_header = (struct ip *)(packet + ETH_BYTES);
}



void print_packet_info(struct Packet_stat* packet_info){
    static unsigned int index_packet = 0; 
    //Print generic info 
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

//

    
    char errbuf[PCAP_ERRBUF_SIZE];
   
    char *dev; // Network device
    pcap_t *handle;

    


/*
    pcap_if_t **list_dev;
    pcap_findalldevs(list_dev,errbuf_);


    for (pcap_if_t* curr_dev = *list_dev; curr_dev->next != NULL; curr_dev = curr_dev->next)
    {
        printf("Device : %s\n",curr_dev->name);
        printf("  Description : %s\n",curr_dev->description);
    }



    pcap_freealldevs(*list_dev);


*/

    time_t start_time;




    // Record the start time
    time(&start_time);

    int option;
    int icmp_mode = 0;
    int run_mode = 0;
    int udp_mode = 0;

    // Parse command-line arguments
    while ((option = getopt(argc, argv, "irum")) != -1) {
        switch (option) {
            case 'i':
                icmp_mode = 1;
                break;
            case 'r':
                run_mode = 1;
                break;
            case 'u' : 
                udp_mode = 1;
                break;
            default:
                fprintf(stderr, "Usage: %s -i -r\n", argv[0]);
                return 1;
        }
    }

 
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        printf("Error finding default device: %s\n", errbuf);
        return 1;
    }

    // Open the capture handle
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Could not open device %s: %s\n", dev, errbuf);
        return 1;
    }

     printf("Running custom code...\n");
        run_mode_packet_callback(handle);

    // Determine which function to run based on arguments
    if (icmp_mode) {
        icmp_packet_callback(handle);
    } else if (run_mode) {
       
    } else if (udp_mode){
        udp_packet_callback(handle);
    } else {
        printf("Usage: %s -i -r -u\n", argv[0]);
    }

    // Close the capture handle
    pcap_close(handle);

    return 0;
}





// ______________________________
// -i 
void icmp_packet_callback(pcap_t *handle) {
    // Set ICMP capture filter
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return;
    }

    // Start capturing ICMP packets
    printf("Press 's' to stop sniffing ICMP packets...\n");
    pcap_loop(handle, 0, packet_callback, NULL);
}
// -u
void udp_packet_callback(pcap_t *handle) {
    struct bpf_program fp;
    char filter_exp[] = "udp";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return;
    }

    // Start capturing ICMP packets
    printf("Press 's' to stop sniffing UDP packets...\n");
    pcap_loop(handle, 0, packet_callback, NULL);
}

//-r
void run_mode_packet_callback(pcap_t *handle){
    printf("Press 's' to stop sniffing ALL packets...\n");
    pcap_loop(handle, 0, packet_callback, NULL);

}


// ______________________________
