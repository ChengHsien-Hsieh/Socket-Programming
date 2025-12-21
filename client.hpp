#pragma once
#include "network_utils.hpp"
#include "message_store.hpp"
#include "crypto_utils.hpp"
#include <string>
#include <atomic>
#include <mutex>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define LOCAL_HOST "127.0.0.1"
#define DEFAULT_PORT 8888
#define BACKLOG 10

/* Protocol definitions */
enum CommandType {REGISTER, LOGIN, LOGOUT, LIST, GET_ADDR, UNKNOWN, CREATE_ROOM, JOIN_ROOM, LEAVE_ROOM, LIST_ROOMS, GROUP_MSG};
enum ResponseCode {SUCCESS, ERROR};
enum ErrorCode {USER_EXISTS, USER_NOT_FOUND, WRONG_PASSWORD, ALREADY_ONLINE, NOT_ONLINE, MUST_LOGIN_FIRST, MUST_LOGOUT_FIRST, UNKNOWN_COMMAND, ROOM_EXISTS, ROOM_NOT_FOUND, NOT_IN_ROOM};

/* P2P Chat Protocol */
enum P2PChatType {CHAT_REQUEST, CHAT_ACCEPT, CHAT_REJECT, CHAT_MSG, CHAT_END};

/* Client state for P2P chat */
enum ClientState {STATE_NORMAL, STATE_WAITING_ACCEPT, STATE_IN_CHAT, STATE_PENDING_REQUEST};

/* Main chat client class - coordinates all components */
class ChatClient {
private:
    /* Server connection */
    int server_fd;
    bool should_continue;
    std::string logged_in_name;
    CryptoSession server_crypto;        // Encrypted session with server
    
    /* P2P listening */
    int listen_fd;
    int listen_port;
    pthread_t listen_thread;
    std::atomic<bool> thread_running;
    
    /* P2P chat session */
    std::atomic<ClientState> client_state;
    int chat_fd;                        // Active chat connection (-1 if none)
    std::string chat_partner;           // Name of current chat partner
    std::mutex chat_mutex;              // Protect chat state
    CryptoSession chat_crypto;          // Encrypted session with chat partner
    
    /* Chat receive thread (active during chat mode) */
    pthread_t chat_recv_thread;
    std::atomic<bool> chat_recv_running;
    
    /* Pending chat request (when someone requests to chat with us) */
    int pending_request_fd;             // FD of pending request (-1 if none)
    std::string pending_requester;      // Name of requester
    
    /* Message storage */
    MessageStore message_store;
    
    /* Error messages */
    static constexpr const char* ERROR_MESSAGES[] = {"User already exists", "User not found", "Wrong password", "User already online", "User not online", "You must login first", "You must logout first", "Unknown command", "Room already exists", "Room not found", "You are not in this room"};

public:
    ChatClient(const std::string& server_ip, int server_port);
    ~ChatClient();
    
    /* Main interface */
    void run();  // Main loop handling both normal and chat modes

private:
    /* Command handlers (normal mode) */
    void handle_normal_command(const std::string& command);
    void cmd_register(const std::string& name, const std::string& password);
    void cmd_login(const std::string& name, const std::string& password, const std::string& port_str);
    void cmd_logout();
    void cmd_list();
    void cmd_send(const std::string& target_name, const std::string& message);
    void cmd_messages(const std::string& room_name);
    void cmd_quit();
    void cmd_unknown();
    
    /* Group chat commands */
    void cmd_create_room(const std::string& room_name);
    void cmd_join_room(const std::string& room_name);
    void cmd_leave_room(const std::string& room_name);
    void cmd_list_rooms();
    void cmd_group_send(const std::string& room_name, const std::string& message);
    
    /* P2P Chat commands */
    void cmd_chat(const std::string& target_name);
    void cmd_accept();
    void cmd_reject();
    void enter_chat_mode();
    void handle_chat_input(const std::string& input);
    void exit_chat_mode();
    void start_chat_recv_thread();
    void stop_chat_recv_thread();
    static void* chat_recv_thread_func(void* arg);
    
    /* P2P listening */
    bool create_listening_socket(int port);
    void close_listening_socket();
    void start_listen_thread();
    void stop_listen_thread();
    static void* listen_thread_func(void* arg);
    void handle_p2p_connection(int peer_fd);
    
    /* P2P chat session helpers */
    void handle_chat_request(int peer_fd, const std::string& requester_name);
    void handle_chat_message(const std::string& message);
    void handle_chat_end();
    
    /* Helper methods */
    bool send_to_server(const std::string& message);
    bool recv_from_server(std::string& response);
    std::string get_user_address(const std::string& username);
    void print_error_message(int error_code);
    
    /* Encryption key exchange */
    bool perform_key_exchange_with_server();
    bool perform_key_exchange_as_initiator(int peer_fd, CryptoSession& crypto);
    bool perform_key_exchange_as_responder(int peer_fd, CryptoSession& crypto);
    
    /* Cleanup helper */
    void ERR_EXIT(const char* msg);
};