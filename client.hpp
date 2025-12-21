#pragma once
#include "network_utils.hpp"
#include "message_store.hpp"
#include "p2p_handler.hpp"
#include <string>

#define LOCAL_HOST "127.0.0.1"
#define DEFAULT_PORT 8888

/* Protocol definitions */
enum CommandType {REGISTER, LOGIN, LOGOUT, LIST, GET_ADDR, UNKNOWN, CREATE_ROOM, JOIN_ROOM, LEAVE_ROOM, LIST_ROOMS, GROUP_MSG};
enum ResponseCode {SUCCESS, ERROR};
enum ErrorCode {USER_EXISTS, USER_NOT_FOUND, WRONG_PASSWORD, ALREADY_ONLINE, NOT_ONLINE, MUST_LOGIN_FIRST, MUST_LOGOUT_FIRST, UNKNOWN_COMMAND, ROOM_EXISTS, ROOM_NOT_FOUND, NOT_IN_ROOM};

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
    static constexpr const char* ERROR_MESSAGES[] = {"User already exists", "User not found", "Wrong password", "User already online", "User not online", "You must login first", "You must logout first", "Unknown command", "Room already exists", "Room not found", "You are not in this room"};

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
    
    /* Group chat commands */
    void cmd_create_room(const std::string& room_name);
    void cmd_join_room(const std::string& room_name);
    void cmd_leave_room(const std::string& room_name);
    void cmd_list_rooms();
    void cmd_group_send(const std::string& room_name, const std::string& message);
    
    /* Helper methods */
    bool send_to_server(const std::string& message);
    bool recv_from_server(std::string& response);
    std::string get_user_address(const std::string& username);
    void print_error_message(int error_code);
    
    /* Cleanup helper */
    void ERR_EXIT(const char* msg);
};