#include "Errors.h"
#include <iostream>
#include <netinet/in.h>
#include <cstring>
#include <ncurses.h>
#include <thread>

using namespace std;

int yMax, xMax;

int getLineFromBuffer(const char *buf) {
    const char *it = strchr(buf, ':');
    if (it == nullptr)
        return -1;
    int line = 0;
    for (int i = 0; buf[i] != ':'; i++)
        line = line * 10 + (buf[i] - '0');
    return line;
}

char bufWithSpace[LINE_MAX];

const pair<string, int> offsets[] = {{"Last", 25},
                                     {"Avg",  18},
                                     {"Best", 12},
                                     {"Wrst", 5}};

void printBufToScreen(char *buf) {
    int line = getLineFromBuffer(buf);
    removeNewLine(buf);
    if (line == -1) {
        // received error, terminate
        mvwprintw(stdscr, 1, 0, bufWithSpace);
        mvwprintw(stdscr, 1, 0, buf);
        refresh();
        nodelay(stdscr, false);
        getch();
        endwin();
        exit(0);
    }

    line++;
    mvwprintw(stdscr, line, 0, bufWithSpace);

    char *p = strtok(buf, ":");
    for (int i = 0; p != nullptr && i - 2 < 4; i++, p = strtok(nullptr, ":")) {
        if (i == 0)
            mvwprintw(stdscr, line, 0, p);
        else if (i == 1 && p[0] == '-') {
            mvwprintw(stdscr, line, 0, bufWithSpace);
            break;
        } else if (i == 1)
            mvwprintw(stdscr, line, 3, p);
        else if (i == 2 && p[0] == '-') {
            mvwprintw(stdscr, line, xMax - 10, "*.*");
            break;
        } else if (i >= 2) {
            mvwprintw(stdscr, line, xMax - offsets[i - 2].second, p);
        }
    }
    refresh();
}

void readClientInput(int sockFd, sockaddr_in serverAddress) {
    fd_set fds;
    FD_ZERO(&fds);
    while (true) {
        timeval tv = {0, 100000}; // a tenth of a second
        FD_SET(STDIN_FILENO, &fds);
        int n = Select(STDIN_FILENO + 1, &fds, nullptr, nullptr, &tv);
        if (n == 1) {
            char c = getch();
            if (c != ERR) {
                if (islower(c))
                    c = (char) toupper(c);
                if (c == 'R' || c == 'P' || c == 'D') {
                    Sendto(sockFd, &c, 1, 0, (SA *) &serverAddress, sizeof(serverAddress));
                } else if (c == 'Q') {
                    Sendto(sockFd, &c, 1, 0, (SA *) &serverAddress, sizeof(serverAddress));
                    endwin();
                    exit(0);
                }
            }
        }
    }
}

[[noreturn]] void updateClient(int sockFd) {
    char recvBuf[LINE_MAX];
    while (true) {
        readline(sockFd, recvBuf, LINE_MAX);
        printBufToScreen(recvBuf);
    }
}

void interactWithServer(char *ipAddressToSend, int sockFd, sockaddr_in serverAddress) {
    addEndLine(ipAddressToSend);
    Write(sockFd, ipAddressToSend, strlen(ipAddressToSend));
    thread clientThread(readClientInput, sockFd, serverAddress), serverThread(updateClient, sockFd);
    clientThread.join();
    serverThread.join();
}

void printMenu() {
    mvwprintw(stdscr, 0, 0, "Keys: R -> reset trace     P -> use ICMP ping     D -> DNS on/off     Q -> quit");
    mvwprintw(stdscr, 1, 0, "Host");
    for (const auto &it: offsets)
        mvwprintw(stdscr, 1, xMax - it.second, it.first.c_str());
    refresh();
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s IP/domain\n", argv[0]);
        return 0;
    }
    initscr();
    cbreak();
    noecho();
    nodelay(stdscr, true);

    getmaxyx(stdscr, yMax, xMax);
    memset(bufWithSpace, ' ', xMax);
    printMenu();

    int sockFd;
    sockaddr_in serverAddress{};

    sockFd = Socket(AF_INET, SOCK_STREAM, 0);
    bzero(&serverAddress, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(SERVER_PORT);
    Inet_pton(AF_INET, IP_ADDRESS, &serverAddress.sin_addr);
    Connect(sockFd, (SA *) &serverAddress, sizeof(serverAddress));


    interactWithServer(argv[1], sockFd, serverAddress);

    endwin();
    return 0;
}

