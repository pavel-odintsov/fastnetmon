#include <fstream>
#include <iostream>
#include <ncurses.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unistd.h>

#include <boost/program_options.hpp>

std::string cli_stats_ipv4_file_path = "/tmp/fastnetmon.dat";

std::string cli_stats_ipv6_file_path = "/tmp/fastnetmon_ipv6.dat";

int main(int argc, char** argv) {
    bool ipv6_mode = false;

    namespace po = boost::program_options;

    try {
        // clang-format off
        po::options_description desc("Allowed options");
        desc.add_options()
        ("help", "produce help message")
        ("ipv6", "switch to IPv6 mode");
        // clang-format on

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm); 
        po::notify(vm);

        if (vm.count("help")) {
            std::cout << desc << std::endl;
            exit(EXIT_SUCCESS);
        }

        if (vm.count("ipv6")) {
            ipv6_mode = true;
        }
    } catch (po::error& e) {
        std::cerr << "ERROR: " << e.what() << std::endl << std::endl;
        exit(EXIT_FAILURE);
    }

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


        std::string cli_stats_file_path = cli_stats_ipv4_file_path;

        if (ipv6_mode) {
            cli_stats_file_path = cli_stats_ipv6_file_path;
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
