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
    bool should_continue;
    int listen_fd;  // P2P listening socket
    int listen_port;  // Port number for P2P

public:
    ServerConnection(const std::string& server_ip, int server_port);
    ~ServerConnection();
    void handle_command(const std::string& command);
    void send_line(const std::string& message);
    bool recv_line(std::string& out);
    bool continued() const { return should_continue; }
    
private:
    bool create_listening_socket(int port);  // Create and bind listening socket
    void close_listening_socket();           // Close listening socket
    void ERR_EXIT(const char *msg);          // Error exit with cleanup
};