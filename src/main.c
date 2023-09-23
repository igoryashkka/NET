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
void init_pcap(){
    //paste here init code of pcap
}


 int X = 1000;

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *dev;
    pcap_t *handle;
   

  
    printf("mode : %d",select_mode(argc,argv));

    
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

  
    run_main_menu(handle,argv);
    run_gui_gtk();

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}


// ______________________________
