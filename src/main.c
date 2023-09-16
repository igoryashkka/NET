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

GtkApplication *app;
int status;


GtkWidget *textview;  // Declare textview as a global variable
GtkWidget *scrolled_window; // Declare scrolled_window as a global variable

// Global char array
char text[200] = ""; // You can initialize it with your initial content


gboolean update_textview_periodically(gpointer data) {
    // Get the text buffer associated with the textview
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(textview);

    // Append the new text to the buffer
    const char *new_text = "New text to append every second\n";
    gtk_text_buffer_insert_at_cursor(buffer, text, -1);

    // Ensure the new text is visible by scrolling to the end
    GtkAdjustment *v_adjust = gtk_scrolled_window_get_vadjustment(scrolled_window);
    gtk_adjustment_set_value(v_adjust, gtk_adjustment_get_upper(v_adjust) - gtk_adjustment_get_page_size(v_adjust));

    // Return TRUE to keep the timeout running
    return TRUE;
}
void open_file(GtkWidget *widget, gpointer data) {
    // Add code to handle opening a file here
}

void quit_app(GtkWidget *widget, gpointer data) {
    gtk_main_quit();
}

void capture_action(){
g_print("capture_action");
}
void filter1_action(){
    g_print("filter1_action");
}


void filter2_action(){
    g_print("filter2_action");
}

void stop_action() {
    g_print("stop_action");
}
void start_action() {
    g_print("start_action");
}
void resume_action() {
    g_print("resume_action");
}

static GtkWidget* create_menu_bar() {
    GtkWidget *menubar = gtk_menu_bar_new();

    // File menu
    GtkWidget *file_menu = gtk_menu_new();
    GtkWidget *file_item = gtk_menu_item_new_with_label("File");
    gtk_menu_item_set_submenu(GTK_MENU_ITEM(file_item), file_menu);
    gtk_menu_shell_append(GTK_MENU_SHELL(menubar), file_item);

    // Add "Open" option to the File menu
    GtkWidget *open_item = gtk_menu_item_new_with_label("Open");
    gtk_menu_shell_append(GTK_MENU_SHELL(file_menu), open_item);
    g_signal_connect(open_item, "activate", G_CALLBACK(open_file), NULL);

    // Capture menu
    GtkWidget *capture_menu = gtk_menu_new();
    GtkWidget *capture_item = gtk_menu_item_new_with_label("Capture");
    gtk_menu_item_set_submenu(GTK_MENU_ITEM(capture_item), capture_menu);
    gtk_menu_shell_append(GTK_MENU_SHELL(menubar), capture_item);

    // Add "Start" option to the Capture menu
    GtkWidget *start_item = gtk_menu_item_new_with_label("Start");
    gtk_menu_shell_append(GTK_MENU_SHELL(capture_menu), start_item);
    g_signal_connect(start_item, "activate", G_CALLBACK(start_action), NULL);

    // Add "Stop" option to the Capture menu
    GtkWidget *stop_item = gtk_menu_item_new_with_label("Stop");
    gtk_menu_shell_append(GTK_MENU_SHELL(capture_menu), stop_item);
    g_signal_connect(stop_item, "activate", G_CALLBACK(stop_action), NULL);

    // Settings menu
    GtkWidget *settings_menu = gtk_menu_new();
    GtkWidget *settings_item = gtk_menu_item_new_with_label("Settings");
    gtk_menu_item_set_submenu(GTK_MENU_ITEM(settings_item), settings_menu);
    gtk_menu_shell_append(GTK_MENU_SHELL(menubar), settings_item);

    // Add "Filter 1" option to the Settings menu
    GtkWidget *filter1_item = gtk_menu_item_new_with_label("Filter 1");
    gtk_menu_shell_append(GTK_MENU_SHELL(settings_menu), filter1_item);
    g_signal_connect(filter1_item, "activate", G_CALLBACK(filter1_action), NULL);

    // Add "Filter 2" option to the Settings menu
    GtkWidget *filter2_item = gtk_menu_item_new_with_label("Filter 2");
    gtk_menu_shell_append(GTK_MENU_SHELL(settings_menu), filter2_item);
    g_signal_connect(filter2_item, "activate", G_CALLBACK(filter2_action), NULL);

    // Create a separate "Exit" item in the menubar
    GtkWidget *exit_item = gtk_menu_item_new_with_label("Exit");
    gtk_menu_shell_append(GTK_MENU_SHELL(menubar), exit_item);
    g_signal_connect(exit_item, "activate", G_CALLBACK(quit_app), NULL);

    return menubar;
}

static void activate(GtkApplication *app, gpointer user_data) {
    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "NET App");
    gtk_window_set_default_size(GTK_WINDOW(window), 800, 600);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(window), vbox);

    GtkWidget *menubar = create_menu_bar(); // Create your menu bar here
    gtk_box_pack_start(GTK_BOX(vbox), menubar, FALSE, FALSE, 0);

    // Create a label for the big title
    GtkWidget *title_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title_label), "<span size='xx-large' weight='bold'>NET APP</span>");
    gtk_box_pack_start(GTK_BOX(vbox), title_label, FALSE, FALSE, 0);

    // Create a scrolled window to hold the textview
    scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window), GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);
    gtk_box_pack_start(GTK_BOX(vbox), scrolled_window, TRUE, TRUE, 0);

    // Create the textview
    textview = gtk_text_view_new();
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(textview), GTK_WRAP_WORD);
    gtk_container_add(GTK_CONTAINER(scrolled_window), textview);

    gtk_widget_show_all(window);

    // Add a timeout to update the textview every second
    g_timeout_add_seconds(1, update_textview_periodically, NULL);

    gtk_main();
}




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
const unsigned char *session_key;

void info_callback(const SSL *ssl, int where, int ret) {
    if (where & SSL_CB_HANDSHAKE_START) {
        SSL_SESSION *session = SSL_get_session(ssl);
        if (session) {
            
            size_t session_key_len;
            SSL_SESSION_get_master_key(session, &session_key, &session_key_len);

            // Now you have the session_key and session_key_len.
            // You can store or use them for decryption later.
            // Note: Ensure proper handling and protection of the session key.
        }
    }
}



void process_packet(const u_char *packet,const struct pcap_pkthdr *pkthdr, struct Packet_stat **packet_info) {

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
    snprintf(text, sizeof(text), "[%d] TS:%ld len:%d\n"
                           "Source MAC: %02X:%02X:%02X:%02X:%02X:%02X | Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n"
                           "Source IP: %s | Destination IP: %s | Protocol: %d\n\n",
            index_packet, (*packet_info).generic_packet_information->ts.tv_sec, (*packet_info).generic_packet_information->len,
            packet_info->eth_header->h_source[0], packet_info->eth_header->h_source[1], packet_info->eth_header->h_source[2],
            packet_info->eth_header->h_source[3], packet_info->eth_header->h_source[4], packet_info->eth_header->h_source[5],
            packet_info->eth_header->h_dest[0], packet_info->eth_header->h_dest[1], packet_info->eth_header->h_dest[2],
            packet_info->eth_header->h_dest[3], packet_info->eth_header->h_dest[4], packet_info->eth_header->h_dest[5],
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
