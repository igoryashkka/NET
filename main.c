#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>
#include <time.h>
/// @brief 
volatile sig_atomic_t stop = 0; // A flag to indicate if capturing should stop

#define ETHERNET_HEADER_SIZE 14

struct PacketStats {
    int totalPackets;
    int totalPayloadSize;
};


void icmp_packet_callback(pcap_t *handle);
void udp_packet_callback(pcap_t *handle);

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct PacketStats *stats = (struct PacketStats *)user_data;

    // Increment total packet count
    stats->totalPackets++;

    // Calculate payload size
    int payload_size = pkthdr->len - ETHERNET_HEADER_SIZE;
    stats->totalPayloadSize += payload_size;

    // Print payload information
    if (payload_size > 0) {
        printf("Packet Payload: %.*s\n", payload_size, packet + ETHERNET_HEADER_SIZE);
    }
}



void packet_callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);



void print_packet_type(int protocol);
   

void process_packet(const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Skip Ethernet header (14 bytes)

    printf("Source IP: %s | Destination IP: %s | Protocol: %d\n",
           inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst), ip_header->ip_p);

    print_packet_type(ip_header->ip_p);
}

void packet_callback(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    process_packet(packet);
}




int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev; // Network device
    pcap_t *handle;

    struct PacketStats stats = {0, 0};

    time_t start_time;

    // Record the start time
    time(&start_time);

    int option;
    int icmp_mode = 0;
    int run_mode = 0;
    int udp_mode = 0;
    int simple_mode = 0;

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
            case 'm' : 
                simple_mode = 1;
                break;
            default:
                fprintf(stderr, "Usage: %s -i -r\n", argv[0]);
                return 1;
        }
    }

    // Get the default network device
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

    // Determine which function to run based on arguments
    if (icmp_mode) {
        icmp_packet_callback(handle);
    } else if (run_mode) {
        printf("Running custom code...\n");
        pcap_loop(handle, 0, packet_callback, NULL);
    } else if (udp_mode){
        udp_packet_callback(handle);
    } else if (simple_mode){
        pcap_loop(handle, 0, packet_handler, (u_char *)&stats);

    // Calculate time elapsed
    time_t currentTime;
    time(&currentTime);
    double timeElapsed = difftime(currentTime, start_time);

    
    double dataTransferRate = (double)stats.totalPayloadSize / timeElapsed;

    
    printf("Total Packets: %d\n", stats.totalPackets);
    printf("Total Payload Size: %d bytes\n", stats.totalPayloadSize);
    printf("Time Elapsed: %.2f seconds\n", timeElapsed);
    printf("Data Transfer Rate: %.2f bytes/second\n", dataTransferRate);

    } else {
        printf("Usage: %s -i -r\n", argv[0]);
    }

    // Close the capture handle
    pcap_close(handle);

    return 0;
}


void print_packet_type(int protocol) {
    switch (protocol) {
        case IPPROTO_ICMP:
            printf("Packet Type: ICMP\n");
            break;
        case IPPROTO_TCP:
            printf("Packet Type: TCP\n");
            break;
        case IPPROTO_UDP:
            printf("Packet Type: UDP\n");
            break;
        default:
            printf("Packet Type: Unknown (%d)\n", protocol);
    }
}



// ______________________________

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



// ______________________________