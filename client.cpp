#include "client.hpp"
#include "ui_utils.hpp"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include <sstream>

int main(int argc, char** argv) {
    std::string server_ip = (argc >= 2) ? argv[1] : LOCAL_HOST;
    int server_port = (argc >= 3) ? std::stoi(argv[2]) : DEFAULT_PORT;

    ChatClient client(server_ip, server_port);

    UI::print_banner("CHAT CLIENT");
    UI::print_line();
    UI::print_info("Available commands:");
    std::cout << Color::DIM << "  register <name> <password>" << Color::RESET << std::endl;
    std::cout << Color::DIM << "  login <name> <password> <port>" << Color::RESET << std::endl;
    std::cout << Color::DIM << "  logout" << Color::RESET << std::endl;
    std::cout << Color::DIM << "  list" << Color::RESET << std::endl;
    std::cout << Color::DIM << "  send <username> <message>" << Color::RESET << std::endl;
    std::cout << Color::DIM << "  messages" << Color::RESET << std::endl;
    std::cout << Color::DIM << "  create_room <room_name>" << Color::RESET << std::endl;
    std::cout << Color::DIM << "  join_room <room_name>" << Color::RESET << std::endl;
    std::cout << Color::DIM << "  leave_room <room_name>" << Color::RESET << std::endl;
    std::cout << Color::DIM << "  list_rooms" << Color::RESET << std::endl;
    std::cout << Color::DIM << "  group_send <room_name> <message>" << Color::RESET << std::endl;
    std::cout << Color::DIM << "  quit" << Color::RESET << std::endl;
    UI::print_line();
    std::cout << std::endl;

    while (client.should_run()) {
        UI::print_prompt();
        std::string command;
        if (!std::getline(std::cin, command))
            break;
        client.handle_command(command);
    }

    UI::print_warning("Connection closed.");
    return 0;
}

/* ===================================
   ChatClient Implementation
   =================================== */

ChatClient::ChatClient(const std::string& server_ip, int server_port): server_fd(-1), should_continue(true), logged_in_name(""), p2p_handler(message_store) {
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
        ERR_EXIT("socket");

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(server_ip.c_str());
    server_addr.sin_port = htons(server_port);

    if (connect(server_fd, (sockaddr*)&server_addr, sizeof(server_addr)) < 0)
        ERR_EXIT("connect");

    UI::print_success("Connected to server at " + server_ip + ":" + std::to_string(server_port));
}

ChatClient::~ChatClient() {
    p2p_handler.stop();
    if (server_fd >= 0)
        close(server_fd);
}

/* ===================================
   Command Dispatcher
   =================================== */

void ChatClient::handle_command(const std::string& command) {
    std::istringstream iss(command);
    std::string cmd_type;
    iss >> cmd_type;

    if (cmd_type == "register") {
        std::string name, password;
        iss >> name >> password;
        cmd_register(name, password);
    }
    else if (cmd_type == "login") {
        std::string name, password, port_str;
        iss >> name >> password >> port_str;
        cmd_login(name, password, port_str);
    }
    else if (cmd_type == "logout")
        cmd_logout();
    else if (cmd_type == "list")
        cmd_list();
    else if (cmd_type == "send") {
        std::string target_name;
        iss >> target_name;
        
        std::string message;
        std::getline(iss, message);
        if (!message.empty() && message[0] == ' ')
            message = message.substr(1);
        
        cmd_send(target_name, message);
    }
    else if (cmd_type == "messages")
        cmd_messages();
    else if (cmd_type == "create_room") {
        std::string room_name;
        iss >> room_name;
        cmd_create_room(room_name);
    }
    else if (cmd_type == "join_room") {
        std::string room_name;
        iss >> room_name;
        cmd_join_room(room_name);
    }
    else if (cmd_type == "leave_room") {
        std::string room_name;
        iss >> room_name;
        cmd_leave_room(room_name);
    }
    else if (cmd_type == "list_rooms")
        cmd_list_rooms();
    else if (cmd_type == "group_send") {
        std::string room_name;
        iss >> room_name;
        
        std::string message;
        std::getline(iss, message);
        if (!message.empty() && message[0] == ' ')
            message = message.substr(1);
        
        cmd_group_send(room_name, message);
    }
    else if (cmd_type == "quit")
        cmd_quit();
    else if (!cmd_type.empty())
        cmd_unknown();
}

/* ===================================
   Command Handlers
   =================================== */

void ChatClient::cmd_register(const std::string& name, const std::string& password) {
    if (name.empty() || password.empty()) {
        UI::print_error("Usage: register <name> <password>");
        return;
    }

    send_to_server(std::to_string(REGISTER) + " " + name + " " + password);
    
    std::string response;
    if (!recv_from_server(response))
        return;

    std::istringstream iss(response);
    int response_code;
    iss >> response_code;
    
    if (response_code == SUCCESS) {
        UI::print_success("Register Success!");
    }
    else {
        int error_code;
        iss >> error_code;
        print_error_message(error_code);
    }
}

void ChatClient::cmd_login(const std::string& name, const std::string& password, const std::string& port_str) {
    if (name.empty() || password.empty() || port_str.empty()) {
        UI::print_error("Usage: login <name> <password> <port>");
        return;
    }

    /* Validate port number */
    int port;
    try {
        size_t pos;
        port = std::stoi(port_str, &pos);
        if (pos != port_str.length()) {
            UI::print_error("Port must be a valid number");
            return;
        }
    } catch (const std::exception&) {
        UI::print_error("Port must be a valid number");
        return;
    }

    if (port < 1024 || port > 65535) {
        UI::print_error("Port must be between 1024 and 65535");
        return;
    }

    /* Setup P2P listening socket */
    if (p2p_handler.has_socket())
        p2p_handler.close_socket();
    
    if (!p2p_handler.create_socket(port)) {
        UI::print_error("Port " + std::to_string(port) + " is not available");
        return;
    }

    send_to_server(std::to_string(LOGIN) + " " + name + " " + password + " " + port_str);
    
    std::string response;
    if (!recv_from_server(response))
        return;

    std::istringstream iss(response);
    int response_code;
    iss >> response_code;
    
    if (response_code == SUCCESS) {
        UI::print_success("Login Success!");
        logged_in_name = name;
        p2p_handler.start();
    }
    else {
        int error_code;
        iss >> error_code;
        print_error_message(error_code);
        p2p_handler.close_socket();
    }
}

void ChatClient::cmd_logout() {
    if (logged_in_name.empty()) {
        UI::print_error("You must login first");
        return;
    }

    send_to_server(std::to_string(LOGOUT) + " " + logged_in_name);
    
    std::string response;
    if (!recv_from_server(response))
        return;

    std::istringstream iss(response);
    int response_code;
    iss >> response_code;
    
    if (response_code == SUCCESS) {
        UI::print_success("Logout Success!");
        p2p_handler.stop();
        logged_in_name.clear();
    }
    else {
        int error_code;
        iss >> error_code;
        print_error_message(error_code);
    }
}

void ChatClient::cmd_list() {
    send_to_server(std::to_string(LIST));
    
    std::string response;
    if (!recv_from_server(response))
        return;

    std::istringstream iss(response);
    int response_code;
    iss >> response_code;
    
    if (response_code == SUCCESS) {
        std::string name;
        std::string output = "Online Users:";
        while (iss >> name)
            output += " " + name;
        UI::print_server_message(output);
    }
    else {
        int error_code;
        iss >> error_code;
        print_error_message(error_code);
    }
}

void ChatClient::cmd_send(const std::string& target_name, const std::string& message) {
    if (logged_in_name.empty()) {
        UI::print_error("You must login first");
        return;
    }
    
    if (target_name.empty()) {
        UI::print_error("Usage: send <username> <message>");
        return;
    }

    if (message.empty()) {
        UI::print_error("Message cannot be empty");
        return;
    }

    /* Get target's address from server */
    std::string addr_info = get_user_address(target_name);
    if (addr_info.empty())
        return;
    
    std::istringstream iss(addr_info);
    std::string ip;
    int port;
    iss >> ip >> port;

    /* Send P2P message */
    if (P2PHandler::send_message(ip, port, logged_in_name, message))
        UI::print_success("Message sent to " + target_name);
    else
        UI::print_error("Failed to send message to " + target_name);
}

void ChatClient::cmd_messages() {
    if (message_store.empty()) {
        UI::print_info("No messages");
        return;
    }
    
    auto messages = message_store.get_all();
    UI::print_info("=== Received Messages ===");
    for (const auto& msg : messages)
        std::cout << "[" << msg.timestamp << "] From " << msg.from << ": " << msg.content << std::endl;
    UI::print_info("=========================");
}

void ChatClient::cmd_quit() {
    UI::print_info("Goodbye!");
    should_continue = false;
}

/* ===================================
   Group Chat Commands
   =================================== */

void ChatClient::cmd_create_room(const std::string& room_name) {
    if (logged_in_name.empty()) {
        UI::print_error("You must login first");
        return;
    }
    
    if (room_name.empty()) {
        UI::print_error("Usage: create_room <room_name>");
        return;
    }
    
    send_to_server(std::to_string(CREATE_ROOM) + " " + room_name);
    
    std::string response;
    if (!recv_from_server(response))
        return;
    
    std::istringstream iss(response);
    int response_code;
    iss >> response_code;
    
    if (response_code == SUCCESS)
        UI::print_success("Room '" + room_name + "' created successfully!");
    else {
        int error_code;
        iss >> error_code;
        print_error_message(error_code);
    }
}

void ChatClient::cmd_join_room(const std::string& room_name) {
    if (logged_in_name.empty()) {
        UI::print_error("You must login first");
        return;
    }
    
    if (room_name.empty()) {
        UI::print_error("Usage: join_room <room_name>");
        return;
    }
    
    send_to_server(std::to_string(JOIN_ROOM) + " " + room_name);
    
    std::string response;
    if (!recv_from_server(response))
        return;
    
    std::istringstream iss(response);
    int response_code;
    iss >> response_code;
    
    if (response_code == SUCCESS)
        UI::print_success("Joined room '" + room_name + "' successfully!");
    else {
        int error_code;
        iss >> error_code;
        print_error_message(error_code);
    }
}

void ChatClient::cmd_leave_room(const std::string& room_name) {
    if (logged_in_name.empty()) {
        UI::print_error("You must login first");
        return;
    }
    
    if (room_name.empty()) {
        UI::print_error("Usage: leave_room <room_name>");
        return;
    }
    
    send_to_server(std::to_string(LEAVE_ROOM) + " " + room_name);
    
    std::string response;
    if (!recv_from_server(response))
        return;
    
    std::istringstream iss(response);
    int response_code;
    iss >> response_code;
    
    if (response_code == SUCCESS)
        UI::print_success("Left room '" + room_name + "' successfully!");
    else {
        int error_code;
        iss >> error_code;
        print_error_message(error_code);
    }
}

void ChatClient::cmd_list_rooms() {
    if (logged_in_name.empty()) {
        UI::print_error("You must login first");
        return;
    }
    
    send_to_server(std::to_string(LIST_ROOMS));
    
    std::string response;
    if (!recv_from_server(response))
        return;
    
    std::istringstream iss(response);
    int response_code;
    iss >> response_code;
    
    if (response_code == SUCCESS) {
        std::string room;
        std::string output = "Available Rooms:";
        while (iss >> room)
            output += " " + room;
        if (output == "Available Rooms:")
            output += " (none)";
        UI::print_server_message(output);
    } else {
        int error_code;
        iss >> error_code;
        print_error_message(error_code);
    }
}

void ChatClient::cmd_group_send(const std::string& room_name, const std::string& message) {
    if (logged_in_name.empty()) {
        UI::print_error("You must login first");
        return;
    }
    
    if (room_name.empty()) {
        UI::print_error("Usage: group_send <room_name> <message>");
        return;
    }
    
    if (message.empty()) {
        UI::print_error("Message cannot be empty");
        return;
    }
    
    send_to_server(std::to_string(GROUP_MSG) + " " + room_name + " " + message);
    
    std::string response;
    if (!recv_from_server(response))
        return;
    
    std::istringstream iss(response);
    int response_code;
    iss >> response_code;
    
    if (response_code == SUCCESS)
        UI::print_success("Message sent to room '" + room_name + "'");
    else {
        int error_code;
        iss >> error_code;
        print_error_message(error_code);
    }
}

void ChatClient::cmd_unknown() {
    send_to_server(std::to_string(UNKNOWN));
    
    std::string response;
    if (!recv_from_server(response))
        return;

    std::istringstream iss(response);
    int response_code;
    iss >> response_code;
    
    if (response_code == ERROR) {
        int error_code;
        iss >> error_code;
        print_error_message(error_code);
    }
}

/* ===================================
   Helper Methods
   =================================== */

bool ChatClient::send_to_server(const std::string& message) {
    if (!NetworkUtils::send_line(server_fd, message)) {
        should_continue = false;
        return false;
    }
    return true;
}

bool ChatClient::recv_from_server(std::string& response) {
    // Keep receiving until we get a non-GROUP_NOTIFY response
    while (true) {
        if (!NetworkUtils::recv_line(server_fd, response)) {
            should_continue = false;
            return false;
        }
        
        // Check if this is a GROUP_NOTIFY message
        if (response.substr(0, 12) == "GROUP_NOTIFY") {
            // Format: "GROUP_NOTIFY room_name sender content"
            std::istringstream iss(response);
            std::string notify_tag, room_name, sender;
            iss >> notify_tag >> room_name >> sender;
            
            std::string content;
            std::getline(iss, content);
            if (!content.empty() && content[0] == ' ')
                content = content.substr(1);
            
            // Store in message queue with room info
            std::string from = "[" + room_name + "] " + sender;
            message_store.add(from, content);
            
            // Display notification
            UI::print_local_message("Group message from " + sender + " in " + room_name);
            
            // Continue reading for more GROUP_NOTIFY or the actual response
            continue;
        }
        
        // This is the actual response (not GROUP_NOTIFY)
        return true;
    }
}

std::string ChatClient::get_user_address(const std::string& username) {
    send_to_server(std::to_string(GET_ADDR) + " " + username);
    
    std::string response;
    if (!recv_from_server(response))
        return "";

    std::istringstream iss(response);
    int response_code;
    iss >> response_code;

    if (response_code == SUCCESS) {
        std::string ip;
        int port;
        iss >> ip >> port;
        return ip + " " + std::to_string(port);
    }
    else {
        int error_code;
        iss >> error_code;
        print_error_message(error_code);
        return "";
    }
}

void ChatClient::print_error_message(int error_code) {
    if (error_code >= 0 && error_code < 11)
        UI::print_error(ERROR_MESSAGES[error_code]);
    else
        UI::print_error("Unknown error");
}

void ChatClient::ERR_EXIT(const char* msg) {
    std::perror(msg);
    if (server_fd >= 0)
        close(server_fd);
    exit(EXIT_FAILURE);
}
