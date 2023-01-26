#pragma once

#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <wait.h>
#include <ctime>
#include <sys/time.h>
#include <vector>
#include <netdb.h>

#define LISTENQ 8
#define SERVER_PORT 9878
#define LINE_MAX 1505
#define MAX_TTL 30
#define IP_ADDRESS "127.0.0.1"

typedef sockaddr SA;

void printHops(const std::vector<in_addr> &v) {
    for (int i = 0; i < (int) v.size(); i++) {
        const auto it = v[i];
        char addr[NI_MAXHOST];
        inet_ntop(AF_INET, &it, addr, INET_ADDRSTRLEN);
        printf("Hop %d, %s\n", i, addr);
    }
    fflush(stdout);
}

int Socket(int family, int type, int protocol) {
    int sock = socket(family, type, protocol);
    if (sock < 0) {
        perror("Error calling socket function");
        exit(-1);
    }
    return sock;
}

ssize_t Read(int fd, void *buf, size_t n) {
    size_t left = n;
    ssize_t haveRead;
    char *p = (char *) buf;
    while (left > 0) {
        if ((haveRead = read(fd, p, left)) < 0) {
            if (errno == EINTR)
                haveRead = 0;
            else {
                perror("Error calling read");
                exit(-1);
            }
        } else if (haveRead == 0)
            break;
        left -= haveRead;
        p += haveRead;
    }
    return ssize_t(n - left);
}

int Select(int nfds, fd_set *readfds,
           fd_set *writefds, fd_set *exceptfds,
           struct timeval *timeout) {
    int n = select(nfds, readfds, writefds, exceptfds, timeout);
    if (n == -1) {
        perror("Error calling select");
        exit(-1);
    }
    return n;
}

ssize_t Write(int fd, const void *buf, size_t n) {
    size_t left = n;
    ssize_t haveWritten;
    const char *p = (const char *) buf;
    while (left > 0) {
        if ((haveWritten = write(fd, p, left)) <= 0) {
            if (haveWritten < 0 && errno == EINTR)
                haveWritten = 0;
            else {
                perror("Error calling write");
                exit(-1);
            }
        }
        left -= haveWritten;
        p += haveWritten;
    }
    return (ssize_t) n;
}

int Bind(int fd, const SA *servAddress, socklen_t length) {
    int n = bind(fd, servAddress, length);
    if (n < 0) {
        perror("Error calling bind");
        exit(-1);
    }
    return n;
}

int Listen(int fd, int n) {
    int r = listen(fd, n);
    if (r < 0) {
        perror("Error calling listen");
        exit(-1);
    }
    return r;
}

int SetSockOpt(int fd, int level, int optname, const void *optval, socklen_t optlen) {
    int n = setsockopt(fd, level, optname, optval, optlen);
    if (n < 0) {
        perror("Error calling setsockopt");
        exit(-1);
    }
    return n;
}

size_t Sendto(int fd, const void *buf, size_t n, int flags, const SA *addr, socklen_t addrLen) {
    size_t a = sendto(fd, buf, n, flags, addr, addrLen);
    if (a < 0) {
        perror("Error calling sendto");
        exit(-1);
    }
    return a;
}

int Accept(int fd, SA *addr, socklen_t *addr_len) {
    int n = accept(fd, addr, addr_len);
    if (n < 0) {
        perror("Error calling accept");
        exit(-1);
    }
    return n;
}

int GetTimeOfDay(timeval *tv, void *tz) {
    int n = gettimeofday(tv, tz);
    if (n < 0) {
        perror("Error calling gettimeofday");
        exit(-1);
    }
    return n;
}

uint16_t in_cksum(uint16_t *addr, int len) {
    int nleft = len;
    uint32_t sum = 0;
    uint16_t *w = addr;
    uint16_t answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1) {
        *(unsigned char *) (&answer) = *(unsigned char *) w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

int Connect(int fd, const SA *addr, socklen_t len) {
    int n = connect(fd, addr, len);
    if (n < 0) {
        perror("Error calling connect");
        exit(-1);
    }
    return n;
}

ssize_t readline(int fd, void *buf, size_t maxLen) {
    ssize_t i, rc;
    char c;
    char *p = (char *) buf;
    for (i = 1; i < maxLen; i++) {
        if ((rc = read(fd, &c, 1)) == 1) {
            *p++ = c;
            if (c == '\n')
                break;
        } else if (rc == 0) {
            *p = '\0';
            return i - 1;
        } else {
            if (errno == EINTR)
                i--;
            else {
                perror("Error in readline");
                exit(-1);
            }
        }
    }
    *p = '\0';
    return i;
}

void addEndLine(char *s) {
    int n = (int) strlen(s);
    s[n] = '\n';
    s[n + 1] = '\0';
}

int Fork() {
    pid_t pid = fork();
    if (pid < 0) {
        perror("Error calling fork");
        exit(-1);
    }
    return pid;
}

int Close(int fd) {
    int n = close(fd);
    if (n < 0) {
        perror("Error calling close");
        exit(-1);
    }
    return n;
}

pid_t Wait(int *statLock) {
    pid_t pid = wait(statLock);
    if (pid < 0) {
        perror("Error calling wait");
        exit(-1);
    }
    return pid;
}

const char *Inet_ntop(int af, const void *cp, char *buf, socklen_t len) {
    const char *n = inet_ntop(af, cp, buf, len);
    if (n == nullptr) {
        perror("Error calling inet_ntop");
        exit(-1);
    }
    return n;
}

int Inet_pton(int af, const char *cp, void *buf) {
    int s = inet_pton(af, cp, buf);
    if (s < 0) {
        perror("Error calling inet_pton");
        exit(-1);
    }
    // s = 0 means address is no good
    return s;
}

void removeNewLine(char *buf) {
    char *p = strchr(buf, '\n');
    *p = '\0';
}
