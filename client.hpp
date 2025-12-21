#pragma once
#include "network_utils.hpp"
#include "message_store.hpp"
#include "p2p_handler.hpp"
#include <string>

#define LOCAL_HOST "127.0.0.1"
#define DEFAULT_PORT 8888

/* Protocol definitions */
enum CommandType {REGISTER, LOGIN, LOGOUT, LIST, GET_ADDR, UNKNOWN};
enum ResponseCode {SUCCESS, ERROR};
enum ErrorCode {USER_EXISTS, USER_NOT_FOUND, WRONG_PASSWORD, ALREADY_ONLINE, NOT_ONLINE, MUST_LOGIN_FIRST, MUST_LOGOUT_FIRST, UNKNOWN_COMMAND};

/* Main chat client class - coordinates all components */
class ChatClient {
private:
    /* Server connection */
    int server_fd;
    bool should_continue;
    std::string logged_in_name;
    
    /* Components */
    MessageStore message_store;
    P2PHandler p2p_handler;
    
    /* Error messages */
    static constexpr const char* ERROR_MESSAGES[] = {"User already exists", "User not found", "Wrong password", "User already online", "User not online", "You must login first", "You must logout first", "Unknown command"};

public:
    ChatClient(const std::string& server_ip, int server_port);
    ~ChatClient();
    
    /* Main command processing */
    void handle_command(const std::string& command);
    bool should_run() const { return should_continue; }

private:
    /* Command handlers */
    void cmd_register(const std::string& name, const std::string& password);
    void cmd_login(const std::string& name, const std::string& password, const std::string& port_str);
    void cmd_logout();
    void cmd_list();
    void cmd_send(const std::string& target_name, const std::string& message);
    void cmd_messages();
    void cmd_quit();
    void cmd_unknown();
    
    /* Helper methods */
    bool send_to_server(const std::string& message);
    bool recv_from_server(std::string& response);
    std::string get_user_address(const std::string& username);
    void print_error_message(int error_code);
    
    /* Cleanup helper */
    void ERR_EXIT(const char* msg);
};