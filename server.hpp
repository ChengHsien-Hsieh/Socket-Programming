#pragma once

#include <string>
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define LOCAL_HOST "127.0.0.1"
#define DEFAULT_PORT 8888
enum CommandType {REGISTER, LOGIN, LOGOUT, LIST, UNKNOWN};

struct User {
    std::string password;
    unsigned short port = 0;
    bool online = false;
};

class Server {
private:
    unsigned short port;
    int listen_fd;
    
public:
    Server(unsigned short p);
    ~Server();
    int accept_conn();
};

class ClientConnection {
private:
    int fd;
    std::string logged_in_name;

public:
    explicit ClientConnection(int client_fd);
    ~ClientConnection();
    void handle_command(const std::string& command);
    void send_line(const std::string& message);
    bool recv_line(std::string& out);
};

/* Thread functions */
void* handle_client(void* arg);
void* handle_signal(void* arg);

/* Helper functions */
inline void err_exit(const char *msg);