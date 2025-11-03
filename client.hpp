#pragma once

#include <string>
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define LOCAL_HOST "127.0.0.1"
#define DEFAULT_PORT 8888
enum CommandType {REGISTER, LOGIN, LOGOUT, LIST, UNKNOWN};

/* ServerConnection class for RAII socket management */
class ServerConnection {
private:
    int fd;
    std::string my_name;
    bool quit_requested;

public:
    ServerConnection(const std::string& server_ip, int server_port);
    ~ServerConnection();
    void handle_command(const std::string& command);
    void send_line(const std::string& message);
    bool recv_line(std::string& out);
    bool continued() const { return !quit_requested; }
};

/* Helper functions */
inline void err_exit(const char *msg);