#ifndef MY_HEADER_H
#define MY_HEADER_H

#include <gtk/gtk.h>


extern GtkApplication *app;
extern char text[200];


GtkWidget* create_menu_bar();
gboolean update_textview_periodically(gpointer data);
void activate(GtkApplication *app, gpointer user_data);

#endif // MY_HEADER_H