#include "gui.h"

static GtkWidget *text_view; // Make text_view global

char text_[200];
// Function to update the text in the GtkTextView
static gboolean update_text_view(gpointer user_data) {
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));
    if (buffer != NULL) {
        gtk_text_buffer_set_text(buffer, text_, -1);
    }
    return G_SOURCE_CONTINUE; // Keep the timer running
}

static void print_hello (GtkWidget *widget,gpointer data){
  g_print ("Hello World\n");
}
static void activate(GtkApplication *app, gpointer user_data) {
    GtkWidget *window;
    GtkWidget *grid;
    GtkWidget *text_view;

    /* Create a new window, and set its title */
    window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "Window");
    gtk_container_set_border_width(GTK_CONTAINER(window), 20);

    /* Increase the initial window size */
    gtk_window_set_default_size(GTK_WINDOW(window), 800, 600);

    /* Create a grid to hold the widgets */
    grid = gtk_grid_new();
    gtk_container_add(GTK_CONTAINER(window), grid);

    /* Create labels for the column headers */
    GtkWidget *label_id = gtk_label_new("ID");
    GtkWidget *label_description = gtk_label_new("Description");
    GtkWidget *label_number = gtk_label_new("Number");

    /* Add the labels to the grid */
    gtk_grid_attach(GTK_GRID(grid), label_id, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), label_description, 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), label_number, 2, 0, 1, 1);

    /* Create example data and populate the table-like layout */
    int row = 1;
    for (int i = 1; i <= 3; i++) {
        char id_text[10];
        snprintf(id_text, sizeof(id_text), "%d", i);

        /* Create labels for ID and Number columns */
        GtkWidget *label_id_value = gtk_label_new(id_text);
        GtkWidget *label_number_value = gtk_label_new("42"); // Example integer value

        /* Create a button for the Description column */
        GtkWidget *button_description = gtk_button_new_with_label("Button");
       // g_signal_connect(button_description, "clicked", G_CALLBACK(print_hello), NULL);

        /* Set the Description column to take up 80% of the available width */
        gtk_widget_set_hexpand(button_description, TRUE);
        gtk_grid_attach(GTK_GRID(grid), label_id_value, 0, row, 1, 1);
        gtk_grid_attach(GTK_GRID(grid), button_description, 1, row, 1, 1);
        gtk_grid_attach(GTK_GRID(grid), label_number_value, 2, row, 1, 1);

        row++;
    }

    /* Create a centered text area (GtkTextView) and add it to the grid */
    text_view = gtk_text_view_new();
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));
    gtk_text_buffer_set_text(buffer, "Hello, GTK!\n", -1); // Set initial text

    // Create marks and apply them to the text buffer
    GtkTextIter start, end;
    gtk_text_buffer_get_start_iter(buffer, &start);
    gtk_text_buffer_get_end_iter(buffer, &end);
    GtkTextMark *mark1 = gtk_text_buffer_create_mark(buffer, "mark1", &start, FALSE);
    GtkTextMark *mark2 = gtk_text_buffer_create_mark(buffer, "mark2", &end, TRUE);

    gtk_grid_attach(GTK_GRID(grid), text_view, 0, row, 3, 1);

    /* Show all widgets */
    gtk_widget_show_all(window);

    // Add a timer to periodically update the text view
    //g_timeout_add_seconds(1, update_text_view, NULL);

    /* Run the GTK main loop */
    gtk_main();
}

