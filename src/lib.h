#ifndef LIB_BIN_
#define  LIB_BIN_

#include <stdbool.h>
#include <stdlib.h> 
#include <string.h>
#include <math.h>
#include <stdio.h>
#include <pcap.h>


extern int option;
extern int icmp_mode;
extern int udp_mode;
extern int run_mode;


int select_mode(int argc, char *argv[]);
void run_main_menu(pcap_t *handle, char *argv[]);




#endif