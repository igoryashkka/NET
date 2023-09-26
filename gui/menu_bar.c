#include "menu_bar.h"





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
    flag_start_capture = 0;
}
void start_action() {
    g_print("start_action");
    flag_start_capture = 1;

}
void resume_action() {
    g_print("resume_action");
}





GtkWidget* create_menu_bar() {
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




