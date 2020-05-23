#include <fstream>
#include <iostream>
#include <ncurses.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unistd.h>

std::string cli_stats_file_path = "/tmp/fastnetmon.dat";

int main() {
    // Init ncurses screen
    initscr();

    // disable any character output
    noecho();

    // hide cursor
    curs_set(0);

    // Do not wait for getch
    timeout(0);

    while (true) {
        sleep(1);

        // clean up screen
        clear();

        int c = getch();

        if (c == 'q') {
            endwin();
            exit(0);
        }

        char* cli_stats_file_path_env = getenv("cli_stats_file_path");

        if (cli_stats_file_path_env != NULL) {
            cli_stats_file_path = std::string(cli_stats_file_path_env);
        }

        std::ifstream reading_file;
        reading_file.open(cli_stats_file_path.c_str(), std::ifstream::in);

        if (!reading_file.is_open()) {
            std::cout << "Can't open fastnetmon stats file: " << cli_stats_file_path;
        }

        std::string line = "";
        std::stringstream screen_buffer;
        while (getline(reading_file, line)) {
            screen_buffer << line << "\n";
        }

        reading_file.close();

        printw(screen_buffer.str().c_str());
        // update screen
        refresh();
    }

    /* End ncurses mode */
    endwin();
}
