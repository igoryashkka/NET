#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>
#include <time.h>
/// @brief 
volatile sig_atomic_t stop = 0; // A flag to indicate if capturing should stop

//////
/// Sniffing ip-packets , filtes : icmp , udp
/// Add another way to represent data 
/// Add more useful infrom in process_packet func
/// Handle start|stop run and choose filter in run-time
//////

#define ETHERNET_HEADER_SIZE 14


void process_packet(const u_char *packet,u_char *user_data,const struct pcap_pkthdr *pkthdr);

struct PacketStats {
    int totalPackets;
    int totalPayloadSize;
};


void icmp_packet_callback(pcap_t *handle); // -i
void udp_packet_callback(pcap_t *handle); // -u
void run_mode_packet_callback(pcap_t *handle);// -r 


void packet_callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    process_packet(packet, user_data,pkthdr);
}




void process_packet(const u_char *packet, u_char *user_data,const struct pcap_pkthdr *pkthdr) {
    printf(" -----------------\n");
    printf(" --- user data ---\n");
    printf(" -----------------\n");

    if(user_data!= NULL){
        for(uint8_t byte = 0; byte <pkthdr->len; byte++){
            printf("%hhu", user_data[byte]);
        }
    }


    printf(" -----------------\n");
    printf(" --- user data ---\n");
    printf(" -----------------\n");


    printf("pkthdr:%d", pkthdr->len);

    struct ethhdr *eth_header = (struct ethhdr *)packet;




    printf("Source MAC: %02X:%02X:%02X:%02X:%02X:%02X | Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth_header->h_source[0], eth_header->h_source[1], eth_header->h_source[2],
           eth_header->h_source[3], eth_header->h_source[4], eth_header->h_source[5],
           eth_header->h_dest[0], eth_header->h_dest[1], eth_header->h_dest[2],
           eth_header->h_dest[3], eth_header->h_dest[4], eth_header->h_dest[5]);
    


    struct ip *ip_header = (struct ip *)(packet + 14); // Skip Ethernet header (14 bytes)

    printf("Source IP: %s | Destination IP: %s | Protocol: %d  \n",
           inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst), ip_header->ip_p);


}





int main(int argc, char *argv[]) {

//

    
    char errbuf[PCAP_ERRBUF_SIZE];
    char errbuf_[PCAP_ERRBUF_SIZE];
    char *dev; // Network device
    pcap_t *handle;

    struct PacketStats stats = {0, 0};



    pcap_if_t **list_dev;
    pcap_findalldevs(list_dev,errbuf_);


    for (pcap_if_t* curr_dev = *list_dev; curr_dev->next != NULL; curr_dev = curr_dev->next)
    {
        printf("Device : %s\n",curr_dev->name);
        printf("  Description : %s\n",curr_dev->description);
    }



    pcap_freealldevs(*list_dev);




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
