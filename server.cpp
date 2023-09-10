#include "Errors.h"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <wait.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <vector>

#define BUF_SIZE 1500
using namespace std;

const int pingOptionalDataLength = 56;

struct Stats {
    int cntResponses = 0;
    double last = 0, avg = 0, best = 100, worst = 0;
    bool stoppedResponding = false;
};
const Stats emptyStats = {0, 0, 0, 100, 0};

void pingSend(int sockFd, const char *ip, int seqNr) {
    // ICMP v4 and v6
    // 0    7 8    15 16        31
    // type    code     checksum
    //   identifier     seq number
    //          optional data

    // code -> 0
    // identifier -> pid of process
    // optional data -> 8 byte timestamp of when the message was sent

    pid_t pid = getpid() & 0xFFFF;
    char bufToSend[BUF_SIZE];

    icmp *icmpReq = (icmp *) bufToSend;
    icmpReq->icmp_type = ICMP_ECHO;
    icmpReq->icmp_code = 0;
    icmpReq->icmp_seq = seqNr;
    icmpReq->icmp_id = pid;
    memset(icmpReq->icmp_data, 0xa5, pingOptionalDataLength);
    GetTimeOfDay((timeval *) icmpReq->icmp_data, nullptr);

    int len = pingOptionalDataLength + ICMP_MINLEN;
    icmpReq->icmp_cksum = 0;
    icmpReq->icmp_cksum = in_cksum((u_int16_t *) icmpReq, len);

    sockaddr_in sendAddress{};
    sendAddress.sin_family = AF_INET;
    Inet_pton(AF_INET, ip, &sendAddress.sin_addr);
    sendto(sockFd, bufToSend, len, 0, (SA *) &sendAddress, sizeof(sendAddress));
}

void tv_sub(timeval *out, const timeval *in) {
    out->tv_usec -= in->tv_usec;
    if (out->tv_usec < 0) {
        out->tv_sec--;
        out->tv_usec += 1000000;
    }
    out->tv_sec -= in->tv_sec;
}

double processICMPReply(char *ptr, ssize_t len, msghdr *, timeval *tvRecv) {
    /*
    0     3  4          7  8 13  14 15 16             31
    version, headerLength, DSCP, ECN,  totalLength
            identification              0,DF,MF, fragmentOffset
            TTL             protocol    headerCheckSum
                        source IP
                        destination IP
------------------------------------------------------------------------ 20 bytes
                        options
                        data

     version      -> 4
     headerLength -> length including options in 32 bit words
     totalLength  -> total length of datagram including header, in bytes

     */
    pid_t pid = getpid();
    ip *ipHeader = (ip *) ptr;
    int ipHeaderLen = ipHeader->ip_hl * 4;
    if (ipHeader->ip_p != IPPROTO_ICMP)
        return -1;
    icmp *icmpHeader = (icmp *) (ptr + ipHeaderLen);
    ssize_t icmpLen = len - ipHeaderLen;
    if (icmpLen < 16)
        return -1;
    if (icmpHeader->icmp_type != ICMP_ECHOREPLY)
        return -1;
    if (icmpHeader->icmp_id != pid)
        return -1;

    auto *tvSend = (timeval *) icmpHeader->icmp_data;
    tv_sub(tvRecv, tvSend);
    double rtt = (double) tvRecv->tv_sec * 1000.0 + (double) tvRecv->tv_usec / 1000.0;
    char fromAddress[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &(ipHeader->ip_src), fromAddress, INET_ADDRSTRLEN) == nullptr) {
        perror("Error calling Inet_ntop");
        exit(-1);
    }
    /*
    printf("%zd bytes from %s: seq = %u, ttl = %d, rtt = %.3f ms\n", icmpLen, fromAddress, icmpHeader->icmp_seq,
           ipHeader->ip_ttl, rtt);
    fflush(stdout);*/
    return rtt;
}

volatile bool gotAlarm;

void handleAlarm(int) {
    gotAlarm = true;
}

double pingRecv(int sockFd) {
    // returns rtt
    SA *rcv = (SA *) calloc(1, sizeof(sockaddr_in));
    char recvBuf[BUF_SIZE], controlBuf[BUF_SIZE];
    iovec iov{};
    msghdr msg{};
    iov.iov_base = recvBuf;
    iov.iov_len = sizeof(recvBuf);

    msg.msg_name = rcv;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = controlBuf;
    if (signal(SIGALRM, handleAlarm) == SIG_ERR) {
        perror("Error calling signal for SIGARLM");
        exit(-1);
    }
    gotAlarm = false;
    alarm(3);
    while (true) {
        if (gotAlarm)
            return -1;
        msg.msg_namelen = sizeof(sockaddr_in);
        msg.msg_controllen = sizeof(controlBuf);
        ssize_t n = recvmsg(sockFd, &msg, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                /*printf("Timeout\n");
                fflush(stdout);*/
                alarm(0);
                return -1;
            } else {
                perror("Error calling recvmsg");
                exit(-1);
            }
        }
        // printf("Received message that might or might not be for us\n");
        // fflush(stdout);
        timeval tval{};
        GetTimeOfDay(&tval, nullptr);
        double rtt = processICMPReply(recvBuf, n, &msg, &tval);
        if (rtt != -1) {
            alarm(0);
            return rtt;
        }
    }
}

int getRawSocket() {
    int sockFd = Socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    int sz = 60 * 1024;
    setsockopt(sockFd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    return sockFd;
}

struct UDP {
    u_short seq, ttl;
    timeval tv;
};

int traceRouteRecv(int recvFd, SA *recvSock, u_short sourcePort, u_short destPort, int seq, timeval *tv) {
    /*
     *  -3 timeout
     *  -2 router
     *  -1 destination
     *  >= 0 some other ICMP code
     */
    char recvBuf[BUF_SIZE];
    ip *ipHeader;
    icmp *icmpHeader;
    if (signal(SIGALRM, handleAlarm) == SIG_ERR) {
        perror("Error calling signal for SIGARLM");
        exit(-1);
    }
    gotAlarm = false;
    alarm(3);
    while (true) {
        if (gotAlarm)
            return -3;
        socklen_t len = sizeof(SA);
        ssize_t n = recvfrom(recvFd, recvBuf, sizeof(recvBuf), 0, recvSock, &len);
        if (n < 0) {
            alarm(0);
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                return -3;
            else {
                perror("Error calling recvfrom when tracing route");
                exit(-1);
            }
        }

        GetTimeOfDay(tv, nullptr);
        ipHeader = (ip *) recvBuf;
        int ipHeaderLength = ipHeader->ip_hl << 2;
        icmpHeader = (icmp *) (recvBuf + ipHeaderLength);
        int icmpLen = (int) n - ipHeaderLength;
        if (icmpLen < 8 + sizeof(ip))
            continue;
        ip *innerIp = (ip *) (recvBuf + ipHeaderLength + 8);
        int ipHeaderLength2 = innerIp->ip_hl << 2;
        if (icmpLen < 8 + ipHeaderLength2 + 4)
            continue;
        auto udp = (struct udphdr *) (recvBuf + ipHeaderLength + 8 + ipHeaderLength2);
        if (icmpHeader->icmp_type == ICMP_TIMXCEED && icmpHeader->icmp_code == ICMP_TIMXCEED_INTRANS) {
            // intermediary router
            if (innerIp->ip_p == IPPROTO_UDP && udp->uh_sport == htons(sourcePort)
                && udp->uh_dport == htons(destPort + seq)) {
                alarm(0);
                return -2;
            }
        } else if (icmpHeader->icmp_type == ICMP_UNREACH) {
            // we have reached the destination
            if (innerIp->ip_p == IPPROTO_UDP && udp->uh_sport == htons(sourcePort) &&
                udp->uh_dport == htons(destPort + seq)) {
                alarm(0);
                if (icmpHeader->icmp_code == ICMP_UNREACH_PORT)
                    return -1;
                else
                    return icmpHeader->icmp_code;
            }
        }
    }
}

int traceSendSockFd, traceRecvSockFd;
sockaddr_in traceSendSock{}, traceRecvSock{}, traceBindSock{};

static bool getSocketsForTraceRoute(char *ip) {
    static bool initialized = false;
    if (!initialized) {
        initialized = true;
        traceSendSockFd = Socket(AF_INET, SOCK_DGRAM, 0);
        traceRecvSockFd = getRawSocket();

        bzero(&traceBindSock, sizeof(traceBindSock));
        bzero(&traceSendSock, sizeof(traceSendSock));
        bzero(&traceRecvSock, sizeof(traceRecvSock));


        // the port will identify the sending process
        const u_short sourcePort = (getpid() & 0xFFFF) | 0x8000;
        traceBindSock.sin_family = AF_INET;
        traceBindSock.sin_port = htons(sourcePort);

        traceSendSock.sin_family = AF_INET;

        // IP could be a domain name
        addrinfo hints{}, *res;
        int n;
        bzero(&hints, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = AI_PASSIVE;
        if (getaddrinfo(ip, nullptr, &hints, &res) == 0) {
            auto *p = (struct sockaddr_in *) res->ai_addr;
            Inet_ntop(AF_INET, &p->sin_addr, ip, LINE_MAX);
        }
        n = Inet_pton(AF_INET, ip, &traceSendSock.sin_addr);
        if (n == 0)
            return false;
        Bind(traceSendSockFd, (SA *) &traceBindSock, sizeof(traceBindSock));
    }
    return true;
}

void updateStats(vector<Stats> &stats, int index, double rtt) {
    // assumes is responding
    auto &it = stats[index];
    it.best = min(it.best, rtt);
    it.avg = (it.avg * it.cntResponses + rtt) / (it.cntResponses + 1);
    it.cntResponses++;
    it.worst = max(it.worst, rtt);
    it.last = rtt;
    it.stoppedResponding = false;
}

bool sameAddress(const sockaddr_in A, const sockaddr_in B) {
    return (memcmp(&A, &B, sizeof(A)) == 0);
}

vector<sockaddr_in> traceRoute(int sockFd, char *ip, vector<Stats> &stats, int &mxVSize) {
    /*
        Return of raw socket:

        ipv4 header -> 20 bytes
        ipv4 options

        ICMPv4 header -> 8 bytes

        IP datagram that generated ICMP error:
        IPv4 header -> 20 bytes
        IPv4 options
        UDP header -> 8 bytes
     */

    // sends UDP messages and receives ICMP

    // cout << "Tracing route\n";
    vector<sockaddr_in> v;
    if (!getSocketsForTraceRoute(ip)) {
        char errorToClient[LINE_MAX] = "IP address or domain name isn't valid\n";
        Write(sockFd, errorToClient, strlen(errorToClient));
        return v;
    }
    const u_short sourcePort = (getpid() & 0xFFFF) | 0x8000;
    timeval T = {3, 0};
    SetSockOpt(traceRecvSockFd, SOL_SOCKET, SO_RCVTIMEO, &T, sizeof(T));

    int seq = 0;
    const u_short destPort = 33434;
    bool reachedDestination = false;
    int mxTtl = 0;
    for (int ttl = 1; ttl <= MAX_TTL && !reachedDestination; ttl++) {
        mxTtl = max(mxTtl, ttl);
        SetSockOpt(traceSendSockFd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int));
        /*printf("Sending probes with ttl: %d\n", ttl);
        fflush(stdout);*/
        for (int probe = 0; probe < 3; probe++) {
            char sendBuf[BUF_SIZE];
            UDP *r = (UDP *) sendBuf;
            r->seq = ++seq;
            r->ttl = ttl;
            timeval tvSend{};
            GetTimeOfDay(&tvSend, nullptr);
            r->tv = tvSend;
            traceSendSock.sin_port = htons(destPort + seq);
            Sendto(traceSendSockFd, sendBuf, sizeof(UDP), 0, (SA *) &traceSendSock, sizeof(traceSendSock));
            timeval tvRecv{};
            int response = traceRouteRecv(traceRecvSockFd, (SA *) &traceRecvSock, sourcePort, destPort, seq, &tvRecv);

            if (response == -3) {
                v.push_back(traceRecvSock);
                size_t index = v.size() - 1;
                stats[index].stoppedResponding = true;
                break;
            } else if (response == -2 || response == -1) {
                if (response == -1)
                    reachedDestination = true;
                if (!v.empty() && sameAddress(v[v.size() - 1], traceRecvSock))
                    continue;

                v.push_back(traceRecvSock);
                tv_sub(&tvRecv, &tvSend);
                double rtt = (double) tvRecv.tv_sec * 1000.0 + (double) tvRecv.tv_usec / 1000.0;
                updateStats(stats, (int) v.size() - 1, rtt);
                break;
            }
        }
    }
    mxVSize = max(mxVSize, (int) v.size());
    return v;
}

void checkForClientInput(int sockFd, bool &sendingPings, bool &dnsOn,
                         vector<Stats> &stats, int &mxVSize, char *ip, vector<sockaddr_in> &v) {
    fd_set fdSet;
    timeval timeoutClientRequest = {0, 0};
    FD_ZERO(&fdSet);
    FD_SET(sockFd, &fdSet);
    int cntReady = Select(sockFd + 1, &fdSet, nullptr, nullptr, &timeoutClientRequest);
    if (cntReady > 0 && FD_ISSET(sockFd, &fdSet)) {
        char command = 0;
        ssize_t n = Read(sockFd, &command, 1);
        if (n == 1) {
            if (command == 'P') {
                sendingPings = true;
                cout << "Switching to pings" << '\n';
            } else if (command == 'R') {
                cout << "Retracing route" << endl;
                for (auto &it: stats)
                    it = emptyStats;
                sendingPings = false;
                v = traceRoute(sockFd, ip, stats, mxVSize);
            } else if (command == 'D') {
                cout << "DNS has been switched" << endl;
                dnsOn = !dnsOn;
            } else if (command == 'Q') {
                close(sockFd);
                exit(0);
            }
        }
    }
}

[[noreturn]] void processRequests(int sockFd) {
    // executed as part of the child process that communicates with a single client
    char buf[LINE_MAX], bufToClient[LINE_MAX], ip[LINE_MAX];
    bool sendingPings = false, dnsOn = true;

    readline(sockFd, buf, LINE_MAX);
    strncpy(ip, buf, LINE_MAX);
    removeNewLine(ip);

    vector<Stats> stats(MAX_TTL, emptyStats);

    int mxVSize = 0;
    vector<sockaddr_in> v = traceRoute(sockFd, ip, stats, mxVSize);
    if (v.empty())
        exit(0);
    // printHops(v);
    while (true) {
        checkForClientInput(sockFd, sendingPings, dnsOn, stats, mxVSize, ip, v);
        for (int i = (int) v.size(); i < mxVSize; i++) {
            snprintf(bufToClient, LINE_MAX, "%d:-\n", i + 1);
            Write(sockFd, bufToClient, strlen(bufToClient));
        }
        if (sendingPings) {
            int seq = 0;
            for (int i = 0; i < (int) v.size(); i++) {
                checkForClientInput(sockFd, sendingPings, dnsOn, stats, mxVSize, ip, v);
                const Stats s = stats[i];
                char addr[NI_MAXHOST], dnsResolve[NI_MAXHOST];
                if (s.stoppedResponding) {
                    strcpy(dnsResolve, "*.*");
                    snprintf(bufToClient, LINE_MAX, "%d:%s:-\n", i + 1, dnsResolve);
                    Write(sockFd, bufToClient, strlen(bufToClient));
                    continue;
                }
                inet_ntop(AF_INET, &v[i].sin_addr, addr, INET_ADDRSTRLEN);

                int rawSockFd = getRawSocket();
                timeval T = {3, 0};
                SetSockOpt(rawSockFd, SOL_SOCKET, SO_RCVTIMEO, &T, sizeof(T));
                pingSend(rawSockFd, addr, ++seq);

                strcpy(dnsResolve, addr);
                if (dnsOn) {
                    getnameinfo((SA *) &v[i], sizeof(v[i]),
                                dnsResolve, NI_MAXHOST, nullptr, 0, 0);
                }

                double rtt = pingRecv(rawSockFd);
                if (rtt == -1) {
                    snprintf(bufToClient, LINE_MAX, "%d:%s:-\n", i + 1, dnsResolve);
                    Write(sockFd, bufToClient, strlen(bufToClient));
                } else {
                    updateStats(stats, i, rtt);
                    snprintf(bufToClient, LINE_MAX, "%d:%s:%.1f:%.1f:%.1f:%.1f:\n",
                             i + 1, dnsResolve, s.last, s.avg, s.best, s.worst);
                    Write(sockFd, bufToClient, strlen(bufToClient));
                }
            }
        } else {
            v = traceRoute(sockFd, ip, stats, mxVSize);
            for (int i = 0; i < (int) v.size(); i++) {
                checkForClientInput(sockFd, sendingPings, dnsOn, stats, mxVSize, ip, v);
                const Stats s = stats[i];
                char addr[NI_MAXHOST], dnsResolve[NI_MAXHOST];
                inet_ntop(AF_INET, &v[i].sin_addr, addr, sizeof(addr));
                if (s.stoppedResponding) {
                    strcpy(addr, "*.*");
                    snprintf(bufToClient, LINE_MAX, "%d:%s:-\n", i + 1, addr);
                    Write(sockFd, bufToClient, strlen(bufToClient));
                } else {
                    // line, ip, last, avg, best, worst
                    strcpy(dnsResolve, addr);
                    if (dnsOn) {
                        getnameinfo((SA *) &v[i], sizeof(v[i]),
                                    dnsResolve, NI_MAXHOST, nullptr, 0, 0);
                    }
                    snprintf(bufToClient, LINE_MAX, "%d:%s:%.1f:%.1f:%.1f:%.1f:\n",
                             i + 1, dnsResolve, s.last, s.avg, s.best, s.worst);
                    Write(sockFd, bufToClient, strlen(bufToClient));
                }
            }
        }
    }
}

void sigChild(int) {
    int stat;
    pid_t pid;
    while ((pid = waitpid(-1, &stat, WNOHANG)) > 0) {
        printf("Child %d terminated\n", pid);
        fflush(stdout);
    }
}

int main() {
    if (signal(SIGCHLD, sigChild) == SIG_ERR) {
        perror("Error calling signal for SIGCHILD");
        exit(-1);
    }

    sockaddr_in servAddress{};
    int listenFd = Socket(AF_INET, SOCK_STREAM, 0);
    bzero(&servAddress, sizeof(servAddress));
    servAddress.sin_family = AF_INET;
    servAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddress.sin_port = htons(SERVER_PORT);
    Bind(listenFd, (SA *) &servAddress, sizeof(servAddress));
    Listen(listenFd, LISTENQ);

    while (true) {
        sockaddr_in clientAddress{};
        socklen_t clientLen = sizeof(clientAddress);
        int connFd = accept(listenFd, (SA *) &clientAddress, &clientLen);
        if (connFd < 0) {
            if (errno == EINTR)
                continue;
            else {
                perror("Error calling accept, not interrupted by syscall");
                exit(-1);
            }
        }
        pid_t childPid = Fork();
        // pid_t childPid = 0;
        if (childPid == 0) {
            // child process
            Close(listenFd);
            processRequests(connFd);
        }
        Close(connFd);
    }
}

