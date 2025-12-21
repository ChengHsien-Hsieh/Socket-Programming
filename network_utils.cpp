#include "network_utils.hpp"
#include <unistd.h>

bool NetworkUtils::send_line(int fd, const std::string& message) {
    std::string line = message + "\n";
    ssize_t total_sent = 0;
    ssize_t len = line.length();
    
    while (total_sent < len) {
        ssize_t sent = send(fd, line.c_str() + total_sent, len - total_sent, 0);
        if (sent <= 0) {
            switch (errno) {
                case EINTR:
                    continue;
                case EAGAIN:
                #if EAGAIN != EWOULDBLOCK
                case EWOULDBLOCK:
                #endif
                    usleep(1000);  // Wait 1ms
                    continue;
                case EPIPE:
                case ECONNRESET:
                    return false;
                default:
                    ERR_EXIT("send");
            }
        }
        total_sent += sent;
    }
    return true;
}

bool NetworkUtils::recv_line(int fd, std::string& out) {
    out.clear();
    char c;
    
    while (true) {
        ssize_t n = recv(fd, &c, 1, 0);
        if (n < 0) {
            switch (errno) {
                case EINTR:
                    continue;
                case EAGAIN:
                #if EAGAIN != EWOULDBLOCK
                case EWOULDBLOCK:
                #endif
                    usleep(1000);  // Wait 1ms
                    continue;
                default:
                    return false;
            }
        }
        else if (n == 0) { // Connection closed
            return false;
        }
        
        if (c == '\n')
            return true;
        out += c;
    }
}

void NetworkUtils::ERR_EXIT(const char* msg) {
    std::perror(msg);
    exit(EXIT_FAILURE);
}
