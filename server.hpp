#pragma once
#include <string>
#include <set>
#include <vector>
#include <unordered_map>
#include <pthread.h>
#include <iostream>
#include <atomic>
#include "crypto_utils.hpp"
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#define LOCAL_HOST "127.0.0.1"
#define DEFAULT_PORT 8888
#define NUM_THREADS 10
#define BACKLOG 10
enum CommandType {REGISTER, LOGIN, LOGOUT, LIST, GET_ADDR, UNKNOWN, CREATE_ROOM, JOIN_ROOM, LEAVE_ROOM, LIST_ROOMS, GROUP_MSG};
enum ResponseCode {SUCCESS, ERROR};
enum ErrorCode {USER_EXISTS, USER_NOT_FOUND, WRONG_PASSWORD, ALREADY_ONLINE, NOT_ONLINE, MUST_LOGIN_FIRST, MUST_LOGOUT_FIRST, UNKNOWN_COMMAND, ROOM_EXISTS, ROOM_NOT_FOUND, NOT_IN_ROOM};

struct User {
    std::string ip;
    unsigned short port = 0;
    std::string password;
    bool online = false;
};

/* Group message structure for pending delivery */
struct GroupMessage {
    std::string room_name;
    std::string sender;
    std::string content;
};

/* Global variables declarations */
extern std::unordered_map<std::string, User> users;
extern pthread_mutex_t users_mutex;
extern std::unordered_map<std::string, std::set<std::string>> chat_rooms;  // RoomName -> {User1, User2...}
extern pthread_mutex_t rooms_mutex;
extern std::unordered_map<std::string, std::vector<GroupMessage>> pending_messages;  // Username -> pending group messages
extern pthread_mutex_t pending_mutex;

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
    CryptoSession crypto;               // Encrypted session with client
    void ERR_EXIT(const char *msg);
    void send_pending_messages();  // Send pending group messages before response
    bool perform_key_exchange();   // Perform ECDH key exchange with client

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