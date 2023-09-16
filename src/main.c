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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <gtk/gtk.h>
#include <pthread.h>
#include "../gui/gui.h"
#include "../network/net.h"

GtkApplication *app;
int status;




// Global char array
char text[200] = ""; // You can initialize it with your initial content





/// @brief 

#define ETH_BYTES 14
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


    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}

void *capture_packets_thread(void *arg) {
    pcap_t *handle = (pcap_t *)arg;

    // Your packet capture code here
    pcap_loop(handle, 0, packet_callback, NULL);

    return NULL;
}


void capture_packets(pcap_t *handle, const char *filter_exp) {
    struct bpf_program fp;

    app = gtk_application_new ("org.gtk.app", G_APPLICATION_FLAGS_NONE);
   
   
    
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
    
    g_signal_connect (app, "activate", G_CALLBACK (activate), NULL);
    status = g_application_run (G_APPLICATION (app), 0, 0);


    g_object_unref (app);
}


// ______________________________
