#ifndef MY_HEADER_H
#define MY_HEADER_H

#include <gtk/gtk.h>
#include "menu_bar.h"



void run_gui_gtk();

void activate(GtkApplication *app, gpointer user_data);

#endif // MY_HEADER_H