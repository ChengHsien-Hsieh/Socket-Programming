#pragma once
#include <string>
#include <pthread.h>
#include <iostream>
#include <atomic>
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define LOCAL_HOST "127.0.0.1"
#define DEFAULT_PORT 8888
#define NUM_THREADS 10
#define BACKLOG 10
enum CommandType {REGISTER, LOGIN, LOGOUT, LIST, GET_ADDR, UNKNOWN};
enum ResponseCode {SUCCESS, ERROR};
enum ErrorCode {USER_EXISTS, USER_NOT_FOUND, WRONG_PASSWORD, ALREADY_ONLINE, NOT_ONLINE, MUST_LOGIN_FIRST, MUST_LOGOUT_FIRST, UNKNOWN_COMMAND};

struct User {
    std::string ip;
    unsigned short port = 0;
    std::string password;
    bool online = false;
};

class Server {
private:
    unsigned short port;
    int listen_fd = -1;
    void ERR_EXIT(const char *msg);

public:
    Server(unsigned short p);
    ~Server();    
    int accept_conn();
    void close_server();
};

class ClientConnection {
private:
    int fd;
    std::string ip;
    std::string logged_in_name = "";
    void ERR_EXIT(const char *msg);

public:
    explicit ClientConnection(int client_fd);
    ~ClientConnection();
    void handle_command(const std::string& command);
    void send_line(const std::string& message);
    bool recv_line(std::string& out);
    void disconnect();
};

/* Signal handler */
void signal_handler(int sig);

/* Worker thread function */
void handle_client(int client_fd, std::atomic<bool>* shutdown_flag);