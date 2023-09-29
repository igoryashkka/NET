///
// -------------------- gui/gui.c -------------------------//
///
// Includes : 
#include "gui.h"
///
//-------------------------------------------------------------//
///
// Global Variables
GtkApplication *app;
GtkWidget *label;
GtkWidget *listbox;

int flag_start_capture = 0;
extern char packet_i[200];
///
//-------------------------------------------------------------//
///
// Internal Functions Defenitions
///
void add_new_box_to_list();
void start_capture(GtkWidget *window);
/// 
void run_gui_gtk(){
    app = gtk_application_new ("org.gtk.app", 0); //  just create instance of applaction - app  (like we can create multi windows app??)
    g_signal_connect (app, "activate", G_CALLBACK (activate), NULL);        //  Connects a #GCallback function to a signal for a particular object. The handler will be called synchronously,      
    g_application_run (G_APPLICATION (app), 0, 0);
   
    g_object_unref (app);
}


gboolean timer_callback(gpointer user_data){
    add_new_box_to_list();
    return G_SOURCE_CONTINUE;
}


void add_new_box_to_list() {
    // Create a new box with some text
    if(flag_start_capture){
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    
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
    g_timeout_add(1000,timer_callback, NULL);
    //g_timeout_add_seconds(1, (GSourceFunc)add_new_box_to_list, NULL);
    
       
    
   
}
///
//CallBacks : 
///
void activate(GtkApplication *app, gpointer user_data) {
    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "NET App");
    gtk_window_set_default_size(GTK_WINDOW(window), 800, 600);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);


    start_capture(window);
    gtk_widget_show_all(window);


    gtk_main();
}
