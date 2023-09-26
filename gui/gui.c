#include "gui.h"

///
// If I remove static will be error : [redefenition] , why???
///

GtkApplication *app;
extern char text[200];
extern char packet_i[200];
extern int flag;

void run_gui_gtk(){

    app = gtk_application_new ("org.gtk.app", G_APPLICATION_DEFAULT_FLAGS); //  just create instance of applaction - app  (like we can create multi windows app??)
    g_signal_connect (app, "activate", G_CALLBACK (activate), NULL);        //  Connects a #GCallback function to a signal for a particular object. The handler will be called synchronously,      
    g_application_run (G_APPLICATION (app), 0, 0);
   

    g_object_unref (app);
}



int static counter = 0;

int flag_start_capture = 0;


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



// Global variables to hold references to the label and its container


// Global variables to hold references to the label and the list box
GtkWidget *label;
GtkWidget *listbox;

void add_new_box_to_list() {
    // Create a new box with some text
    if(flag_start_capture){
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    counter++;
    char _text[200];
    snprintf(_text,200, "%s",packet_i);
    //g_print(" ======= %s )))))))", packet_i);


    GtkWidget *label = gtk_label_new(_text);
    gtk_box_pack_start(GTK_BOX(box), label, TRUE, TRUE, 0);

    // Add the new box to the list box
    gtk_list_box_insert(GTK_LIST_BOX(listbox), box, -1);
    gtk_widget_show_all(box);
    }
    // Re-schedule adding a new box every 1 second
    //g_timeout_add_seconds(1, add_new_box_to_list, NULL);
}

void start_capture(GtkWidget *window) {
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(window), vbox);

    GtkWidget *menubar = create_menu_bar(); // Create your menu bar here
    gtk_box_pack_start(GTK_BOX(vbox), menubar, FALSE, FALSE, 0);

    // Create a label for the big title
    label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(label), "<span size='xx-large' weight='bold'>NET APP</span>");
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

    // Create a scrolled window to hold the list box
    GtkWidget *scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_box_pack_start(GTK_BOX(vbox), scrolled_window, TRUE, TRUE, 0);

    // Create a list box to hold the dynamic content
    listbox = gtk_list_box_new();
    gtk_container_add(GTK_CONTAINER(scrolled_window), listbox);
    gtk_widget_show(listbox);

    // Start adding a new box to the list every 1 second

    g_timeout_add_seconds(1, (GSourceFunc)add_new_box_to_list, NULL);
    
       
    
   
}


void activate(GtkApplication *app, gpointer user_data) {
    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "NET App");
    gtk_window_set_default_size(GTK_WINDOW(window), 800, 600);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    //g_timeout_add_seconds(1, (GSourceFunc)add_new_box_to_list, NULL);

    start_capture(window);
    

    

    gtk_widget_show_all(window);

    
    

    gtk_main();
}
