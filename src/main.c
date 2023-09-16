#include "main.h"


// Global char array
char text[200] = ""; // You can initialize it with your initial content





/// @brief 


//////
/// Sniffing ip-packets , filtes : icmp , udp
/// Add another way to represent data 
/// Add more useful infrom in process_packet func
/// Handle start|stop run and choose filter in run-time
//////
///Need to add help note
//////




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

    run_gui_gtk();

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}


// ______________________________
