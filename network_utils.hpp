#pragma once
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <cerrno>
#include <cstdlib>
#include <cstdio>

/* Network utility class for low-level socket operations */
class NetworkUtils {
public:
    /* Send a line (with '\n' appended) to the given socket
     * Returns true on success, false on connection error */
    static bool send_line(int fd, const std::string& message);
    
    /* Receive a line (until '\n') from the given socket
     * Returns true on success, false on connection closed or error */
    static bool recv_line(int fd, std::string& out);
    
    /* Print error message and exit */
    static void ERR_EXIT(const char* msg);
};
