#include "lib.h"


////
//Extracting payload data in raw chars
//need to encrypt|decode
////
/*
    struct ether_header *eth_header; 
    eth_header = (struct ether_header *) packet; 
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) { 
        printf("Not an IP packet. Skipping...\n\n"); 
       // return; 
    } 
    const u_char *ip_header; 
    const u_char *tcp_header; 
    const u_char *payload; 

    int ip_header_length; 
    int tcp_header_length; 
    int payload_length; 

    ip_header = packet + ETHERNET_HEADER_LENGTH; 
    ip_header_length = ((*ip_header) & 0x0F);
    ip_header_length = ip_header_length * 4; 
    printf("IP header length (IHL) in bytes: %d\n", ip_header_length); 
    
    u_char protocol = *(ip_header + 9); 
    if (protocol != IPPROTO_TCP) { 
        printf("Not a TCP packet. Skipping...\n\n"); 
        //return; 
    } 

    tcp_header = packet + ETHERNET_HEADER_LENGTH + ip_header_length; 
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4; 

    tcp_header_length = tcp_header_length * 4; 
    printf("TCP header length in bytes: %d\n", tcp_header_length); 

     int total_headers_size = ETHERNET_HEADER_LENGTH+ip_header_length+tcp_header_length; 
    printf("Size of all headers combined: %d bytes\n", total_headers_size); 
    payload_length = pkthdr->caplen - 
        (ETHERNET_HEADER_LENGTH + ip_header_length + tcp_header_length); 
    printf("Payload size: %d bytes\n", payload_length); 
    payload = packet + total_headers_size; 
    printf("Memory address where payload begins: %p\n\n", payload); 
 

    if (payload_length > 0) { 
        const u_char *temp_pointer = payload; 
        int byte_count = 0; 
        while (byte_count++ < payload_length) { 
            printf("%c", *temp_pointer); 
            temp_pointer++; 
        } 
        printf("\n"); 
    } 
 
 */