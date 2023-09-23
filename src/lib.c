#include "lib.h"

    int option;
    int icmp_mode = 0;
    int udp_mode = 0;
    int run_mode = 0;
    


void run_main_menu(pcap_t *handle, char *argv[]){
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

}



int select_mode(int argc, char *argv[]){


 // Parse command-line arguments
    while ((option = getopt(argc, argv, "iur")) != -1) {
        switch (option) {
            case 'i':
                icmp_mode = 1;
                break;;
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

    return udp_mode;
}



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
 


 /*
    SSL_CTX *ssl_ctx;
    SSL *ssl;

SSL_library_init();
ERR_load_crypto_strings();
SSL_load_error_strings();


ssl_ctx = SSL_CTX_new(SSLv23_client_method());
ssl = SSL_new(ssl_ctx);

// Set the session key for decryption
SSL_set_session(ssl, session_key);

// Initialize a buffer to hold the decrypted payload
unsigned char decrypted_payload[1024]; // MAX_PAYLOAD_SIZE is the maximum expected payload size

// Decrypt the payload
int result = SSL_read(ssl, decrypted_payload, 1024);
if (result > 0) {
    printf("Decrypted Payload:\n");
    fwrite(decrypted_payload, 1, result, stdout);
} else {
    printf("Decryption failed.\n");
}

SSL_free(ssl);
SSL_CTX_free(ssl_ctx);
ERR_free_strings();

    */


 