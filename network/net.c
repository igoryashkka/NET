///
// -------------------- network/net.c -------------------------//
///
// Includes : 
#include "net.h"
///
//-------------------------------------------------------------//
///
// Global Variables
char packet_i[200];
extern int flag_start_capture; 
///
//-------------------------------------------------------------//
///
// Internal Functions Defenitions
void print_packet_info(struct Packet_stat* packet_info);
void capture_packets(pcap_t *handle, const char *filter_exp);
void packet_callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void process_packet(const u_char *packet,const struct pcap_pkthdr *pkthdr, struct Packet_stat **packet_info);
///
//---------------------------------------------------------//

//
void packet_callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct Packet_stat *packet_info = NULL;
    
    if(flag_start_capture) {
    process_packet(packet, pkthdr, &packet_info);
    print_packet_info(packet_info);
        if(packet_info){
            free(packet_info);
        }
    }
}

void process_packet(const u_char *packet,const struct pcap_pkthdr *pkthdr, struct Packet_stat **packet_info) {

    struct ether_header *eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) { 
        printf("Not an IP packet. Skipping...\n\n"); 
       // return; 
    } 
    const u_char *ip_header = packet + ETHERNET_HEADER_LENGTH; 
    
    int ip_header_length = ((*ip_header) & 0x0F) * 4; 
    
    printf("IP header length (IHL) in bytes: %d\n", ip_header_length); 
    
    u_char protocol = *(ip_header + 9); 
    if (protocol != IPPROTO_TCP) { 
        printf("Not a TCP packet. Skipping...\n\n"); 
        //return; 
    } 

    const u_char *tcp_header = packet + ETHERNET_HEADER_LENGTH + ip_header_length; 
    int tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4; 

    tcp_header_length *= 4; 
    printf("TCP header length in bytes: %d\n", tcp_header_length); 

    int total_headers_size = ETHERNET_HEADER_LENGTH+ip_header_length+tcp_header_length; 
    printf("Size of all headers combined: %d bytes\n", total_headers_size); 
    int payload_length = pkthdr->caplen - total_headers_size; 
    printf("Payload size: %d bytes\n", payload_length); 
    const u_char *payload = packet + total_headers_size; 
    printf("Memory address where payload begins: %p\n\n", payload); 


    if (payload_length > 0) {
        printf("%.*s\n", payload_length, payload);
    }
    

    struct Packet_stat *packet_info_ptr = malloc(sizeof(struct Packet_stat));
    if (packet_info_ptr) {
        packet_info_ptr->generic_packet_information = *pkthdr;
        memcpy(&packet_info_ptr->eth_header, eth_header, sizeof(struct ether_header));
        memcpy(&packet_info_ptr->ip_header, ip_header, sizeof(struct ip));
        *packet_info = packet_info_ptr;
    }
    
    
}



void print_packet_info(struct Packet_stat* packet_info){
    static unsigned int index_packet = 0; 
    //Print generic info 
    //here run-time error
    
    //printf("[%d] TS:%ld ",index_packet, (*packet_info).generic_packet_information->ts.tv_sec);
    //printf("len:%d \n",(*packet_info).generic_packet_information->len);

    
    //Print MAC adresess 
    /*
    printf("Source MAC: %02X:%02X:%02X:%02X:%02X:%02X | Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           packet_info->eth_header->h_source[0], packet_info->eth_header->h_source[1], packet_info->eth_header->h_source[2],
           packet_info->eth_header->h_source[3], packet_info->eth_header->h_source[4], packet_info->eth_header->h_source[5],
           packet_info->eth_header->h_dest[0], packet_info->eth_header->h_dest[1], packet_info->eth_header->h_dest[2],
           packet_info->eth_header->h_dest[3], packet_info->eth_header->h_dest[4], packet_info->eth_header->h_dest[5]);
    
    */
    // Copy the source and destination IP addresses
    //struct in_addr src_addr = packet_info->ip_header->ip_src;
    struct in_addr src_addr  = packet_info->ip_header.ip_src;
    struct in_addr dst_addr = packet_info->ip_header.ip_dst;

    // Convert the copied addresses to strings
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &src_addr, src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst_addr, dst_ip_str, INET_ADDRSTRLEN);


    printf("Source IP: %s | Destination IP: %s | Protocol: %d\n",
           src_ip_str, dst_ip_str, packet_info->ip_header.ip_p);
    
 
    snprintf(packet_i, sizeof(packet_i), "[%d] TS:%ld len:%d\n"
                           "Source IP: %s | Destination IP: %s | Protocol: %d\n\n",
            index_packet, packet_info->generic_packet_information.ts.tv_sec, packet_info->generic_packet_information.len,
            src_ip_str, dst_ip_str, packet_info->ip_header.ip_p);
    


    printf("------------\n----------------\n------------\n");
    printf("text  "); printf("%s", packet_i); //printf(" ==== %d", X);
    printf("------------\n----------------\n------------\n");
    
   index_packet++;
}




void *capture_packets_thread(void *arg) {
    pcap_t *handle = (pcap_t *)arg;

    pcap_loop(handle, 0, packet_callback, NULL);

    return NULL;
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

    pthread_t capture_thread;
    if (pthread_create(&capture_thread, NULL, capture_packets_thread, handle)) {
        fprintf(stderr, "Error creating capture thread\n");
        return;
    }
    
    


}

