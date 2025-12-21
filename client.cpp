#include "client.hpp"
#include "ui_utils.hpp"
#include <unistd.h>
#include <iostream>
#include <sstream>
#include <cstring>

int main(int argc, char** argv) {
    std::string server_ip = (argc >= 2) ? argv[1] : LOCAL_HOST;
    int server_port = (argc >= 3) ? std::stoi(argv[2]) : DEFAULT_PORT;

    ChatClient client(server_ip, server_port);
    client.run();

    UI::print_warning("Connection closed.");
    return 0;
}

/* ===================================
   ChatClient Implementation
   =================================== */

ChatClient::ChatClient(const std::string& server_ip, int server_port)
    : server_fd(-1), should_continue(true), logged_in_name(""),
      listen_fd(-1), listen_port(0), thread_running(false),
      client_state(STATE_NORMAL), chat_fd(-1), chat_partner(""),
      chat_recv_running(false),
      pending_request_fd(-1), pending_requester("") {
    
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
    stop_listen_thread();
    close_listening_socket();
    if (chat_fd >= 0) close(chat_fd);
    if (server_fd >= 0) close(server_fd);
}

/* ===================================
   Main Loop - handles different modes
   =================================== */

void ChatClient::run() {
    UI::print_banner("CHAT CLIENT");
    UI::print_line();
    UI::print_info("Available commands:");
    std::cout << Color::DIM << "  register <name> <password>" << Color::RESET << std::endl;
    std::cout << Color::DIM << "  login <name> <password> <port>" << Color::RESET << std::endl;
    std::cout << Color::DIM << "  logout" << Color::RESET << std::endl;
    std::cout << Color::DIM << "  list" << Color::RESET << std::endl;
    std::cout << Color::DIM << "  chat <username>        - Start P2P chat session" << Color::RESET << std::endl;
    std::cout << Color::DIM << "  accept / reject        - Accept/reject incoming chat request" << Color::RESET << std::endl;
    std::cout << Color::DIM << "  messages <room_name>   - View group chat history" << Color::RESET << std::endl;
    std::cout << Color::DIM << "  create_room <room_name>" << Color::RESET << std::endl;
    std::cout << Color::DIM << "  join_room <room_name>" << Color::RESET << std::endl;
    std::cout << Color::DIM << "  leave_room <room_name>" << Color::RESET << std::endl;
    std::cout << Color::DIM << "  list_rooms" << Color::RESET << std::endl;
    std::cout << Color::DIM << "  group_send <room_name> <message>" << Color::RESET << std::endl;
    std::cout << Color::DIM << "  quit" << Color::RESET << std::endl;
    UI::print_line();
    std::cout << std::endl;

    while (should_continue) {
        ClientState current_state = client_state.load();
        
        if (current_state == STATE_IN_CHAT)
            enter_chat_mode();
        else {
            /* Normal mode */
            if (current_state == STATE_PENDING_REQUEST)
                UI::print_info("Pending chat request from '" + pending_requester + "'. Type 'accept' or 'reject'");
            
            UI::print_prompt();
            std::string command;
            if (!std::getline(std::cin, command))
                break;
            handle_normal_command(command);
        }
    }
}

/* ===================================
   Normal Mode Command Handler
   =================================== */

void ChatClient::handle_normal_command(const std::string& command) {
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
    else if (cmd_type == "chat") {
        std::string target_name;
        iss >> target_name;
        cmd_chat(target_name);
    }
    else if (cmd_type == "accept")
        cmd_accept();
    else if (cmd_type == "reject")
        cmd_reject();
    else if (cmd_type == "send") {
        std::string target_name;
        iss >> target_name;
        std::string message;
        std::getline(iss, message);
        if (!message.empty() && message[0] == ' ')
            message = message.substr(1);
        cmd_send(target_name, message);
    }
    else if (cmd_type == "messages") {
        std::string room_name;
        iss >> room_name;
        cmd_messages(room_name);
    }
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
   P2P Chat Commands
   =================================== */

void ChatClient::cmd_chat(const std::string& target_name) {
    if (logged_in_name.empty()) {
        UI::print_error("You must login first");
        return;
    }
    
    if (target_name.empty()) {
        UI::print_error("Usage: chat <username>");
        return;
    }
    
    if (target_name == logged_in_name) {
        UI::print_error("Cannot chat with yourself");
        return;
    }
    
    ClientState expected = STATE_NORMAL;
    if (!client_state.compare_exchange_strong(expected, STATE_WAITING_ACCEPT)) {
        if (expected == STATE_IN_CHAT)
            UI::print_error("Already in a chat session");
        else if (expected == STATE_WAITING_ACCEPT)
            UI::print_error("Already waiting for a chat response");
        else if (expected == STATE_PENDING_REQUEST)
            UI::print_error("You have a pending chat request. Accept or reject it first.");
        return;
    }
    
    /* Get target's P2P address from server */
    std::string addr_info = get_user_address(target_name);
    if (addr_info.empty()) {
        client_state = STATE_NORMAL;
        return;
    }
    
    std::istringstream iss(addr_info);
    std::string ip;
    int port;
    iss >> ip >> port;
    
    /* Connect to target's P2P listening port */
    int peer_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (peer_fd < 0) {
        UI::print_error("Failed to create socket");
        client_state = STATE_NORMAL;
        return;
    }
    
    sockaddr_in peer_addr{};
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_addr.s_addr = inet_addr(ip.c_str());
    peer_addr.sin_port = htons(port);
    
    if (connect(peer_fd, (sockaddr*)&peer_addr, sizeof(peer_addr)) < 0) {
        UI::print_error("Failed to connect to " + target_name);
        close(peer_fd);
        client_state = STATE_NORMAL;
        return;
    }
    
    /* Send CHAT_REQUEST */
    std::string request = std::to_string(CHAT_REQUEST) + " " + logged_in_name;
    if (!NetworkUtils::send_line(peer_fd, request)) {
        UI::print_error("Failed to send chat request");
        close(peer_fd);
        client_state = STATE_NORMAL;
        return;
    }
    
    UI::print_info("Chat request sent to " + target_name + ". Waiting for response...");
    
    /* Wait for response (blocking) */
    std::string response;
    if (!NetworkUtils::recv_line(peer_fd, response)) {
        UI::print_error("Connection closed by " + target_name);
        close(peer_fd);
        client_state = STATE_NORMAL;
        return;
    }
    
    std::istringstream resp_iss(response);
    int resp_type;
    resp_iss >> resp_type;
    
    if (resp_type == CHAT_ACCEPT) {
        UI::print_success(target_name + " accepted your chat request!");
        UI::print_info("You are now chatting with " + target_name + ". Type 'exit' to leave.");
        
        {
            std::lock_guard<std::mutex> lock(chat_mutex);
            chat_fd = peer_fd;
            chat_partner = target_name;
            client_state = STATE_IN_CHAT;
        }
        start_chat_recv_thread();
    }
    else if (resp_type == CHAT_REJECT) {
        std::string reason;
        std::getline(resp_iss, reason);
        if (!reason.empty() && reason[0] == ' ')
            reason = reason.substr(1);
        
        if (reason == "busy")
            UI::print_warning(target_name + " is busy (already in a chat)");
        else
            UI::print_warning(target_name + " rejected your chat request");
        
        close(peer_fd);
        client_state = STATE_NORMAL;
    }
    else {
        UI::print_error("Unexpected response from " + target_name);
        close(peer_fd);
        client_state = STATE_NORMAL;
    }
}

void ChatClient::cmd_accept() {
    if (client_state != STATE_PENDING_REQUEST) {
        UI::print_error("No pending chat request to accept");
        return;
    }
    
    {
        std::lock_guard<std::mutex> lock(chat_mutex);
        
        /* Send CHAT_ACCEPT */
        std::string response = std::to_string(CHAT_ACCEPT);
        if (!NetworkUtils::send_line(pending_request_fd, response)) {
            UI::print_error("Failed to accept chat request");
            close(pending_request_fd);
            pending_request_fd = -1;
            pending_requester.clear();
            client_state = STATE_NORMAL;
            return;
        }
        
        UI::print_success("You are now chatting with " + pending_requester + ". Type 'exit' to leave.");
        
        chat_fd = pending_request_fd;
        chat_partner = pending_requester;
        pending_request_fd = -1;
        pending_requester.clear();
        client_state = STATE_IN_CHAT;
    }
    
    /* Start receive thread - lock released */
    start_chat_recv_thread();
}

void ChatClient::cmd_reject() {
    if (client_state != STATE_PENDING_REQUEST) {
        UI::print_error("No pending chat request to reject");
        return;
    }
    
    std::lock_guard<std::mutex> lock(chat_mutex);
    
    /* Send CHAT_REJECT */
    std::string response = std::to_string(CHAT_REJECT) + " declined";
    NetworkUtils::send_line(pending_request_fd, response);
    
    close(pending_request_fd);
    pending_request_fd = -1;
    
    UI::print_info("Rejected chat request from " + pending_requester);
    pending_requester.clear();
    client_state = STATE_NORMAL;
}

void ChatClient::enter_chat_mode() {
    /* Chat mode: handle both user input and incoming messages */
    UI::print_chat_prompt();
    
    std::string input;
    if (!std::getline(std::cin, input)) {
        exit_chat_mode();
        return;
    }
    
    handle_chat_input(input);
}

void ChatClient::handle_chat_input(const std::string& input) {
    if (input == "exit") {
        /* Send CHAT_END to peer */
        std::string msg = std::to_string(CHAT_END);
        NetworkUtils::send_line(chat_fd, msg);
        exit_chat_mode();
        return;
    }
    
    if (input.empty())
        return;
    
    /* Send CHAT_MSG */
    std::string msg = std::to_string(CHAT_MSG) + " " + input;
    if (!NetworkUtils::send_line(chat_fd, msg)) {
        UI::print_error("Failed to send message. Connection lost.");
        exit_chat_mode();
        return;
    }
}

void ChatClient::exit_chat_mode() {
    /* Check if already exited */
    if (client_state != STATE_IN_CHAT && chat_fd < 0) {
        return;
    }
    
    /* Shutdown socket first to interrupt blocking recv */
    {
        std::lock_guard<std::mutex> lock(chat_mutex);
        if (chat_fd >= 0) {
            shutdown(chat_fd, SHUT_RDWR);
        }
    }
    
    /* Stop receive thread (will unblock from recv now) */
    stop_chat_recv_thread();
    
    std::lock_guard<std::mutex> lock(chat_mutex);
    
    if (chat_fd >= 0) {
        close(chat_fd);
        chat_fd = -1;
    }
    
    if (!chat_partner.empty()) {
        UI::print_info("Left chat with " + chat_partner);
        chat_partner.clear();
    }
    client_state = STATE_NORMAL;
}

/* ===================================
   Chat Receive Thread
   =================================== */

void ChatClient::start_chat_recv_thread() {
    if (chat_recv_running)
        return;
    
    chat_recv_running = true;
    pthread_create(&chat_recv_thread, nullptr, chat_recv_thread_func, this);
}

void ChatClient::stop_chat_recv_thread() {
    if (!chat_recv_running)
        return;
    
    chat_recv_running = false;
    
    /* The recv will be interrupted when chat_fd is closed */
    pthread_join(chat_recv_thread, nullptr);
}

void* ChatClient::chat_recv_thread_func(void* arg) {
    ChatClient* self = static_cast<ChatClient*>(arg);
    
    while (self->chat_recv_running && self->client_state == STATE_IN_CHAT) {
        std::string message;
        if (!NetworkUtils::recv_line(self->chat_fd, message)) {
            /* Connection lost */
            if (self->chat_recv_running && self->client_state == STATE_IN_CHAT) {
                self->chat_recv_running = false;
                
                std::cout << "\r\033[K";  /* Clear current line */
                UI::print_warning(self->chat_partner + " has disconnected");
                
                std::lock_guard<std::mutex> lock(self->chat_mutex);
                if (self->chat_fd >= 0) {
                    close(self->chat_fd);
                    self->chat_fd = -1;
                }
                self->chat_partner.clear();
                self->client_state = STATE_NORMAL;
            }
            break;
        }
        
        std::istringstream iss(message);
        int msg_type;
        iss >> msg_type;
        
        if (msg_type == CHAT_MSG) {
            std::string content;
            std::getline(iss, content);
            if (!content.empty() && content[0] == ' ')
                content = content.substr(1);
            
            self->handle_chat_message(content);
        }
        else if (msg_type == CHAT_END) {
            self->chat_recv_running = false;
            
            std::cout << "\r\033[K";  /* Clear current line */
            UI::print_warning(self->chat_partner + " has left the chat");
            
            std::lock_guard<std::mutex> lock(self->chat_mutex);
            if (self->chat_fd >= 0) {
                close(self->chat_fd);
                self->chat_fd = -1;
            }
            self->chat_partner.clear();
            self->client_state = STATE_NORMAL;
            break;
        }
    }
    
    return nullptr;
}

/* ===================================
   P2P Listening Thread
   =================================== */

bool ChatClient::create_listening_socket(int port) {
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0)
        return false;

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(listen_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        close(listen_fd);
        listen_fd = -1;
        return false;
    }

    if (listen(listen_fd, BACKLOG) < 0) {
        close(listen_fd);
        listen_fd = -1;
        return false;
    }

    listen_port = port;
    return true;
}

void ChatClient::close_listening_socket() {
    if (listen_fd >= 0) {
        close(listen_fd);
        listen_fd = -1;
        listen_port = 0;
    }
}

void ChatClient::start_listen_thread() {
    if (thread_running)
        return;
    
    thread_running = true;
    pthread_create(&listen_thread, nullptr, listen_thread_func, this);
}

void ChatClient::stop_listen_thread() {
    if (!thread_running)
        return;
    
    thread_running = false;
    
    /* Interrupt blocking accept by closing socket */
    if (listen_fd >= 0) {
        shutdown(listen_fd, SHUT_RDWR);
    }
    
    pthread_join(listen_thread, nullptr);
}

void* ChatClient::listen_thread_func(void* arg) {
    ChatClient* self = static_cast<ChatClient*>(arg);
    
    while (self->thread_running) {
        sockaddr_in peer_addr{};
        socklen_t addr_len = sizeof(peer_addr);
        
        int peer_fd = accept(self->listen_fd, (sockaddr*)&peer_addr, &addr_len);
        if (peer_fd < 0) {
            if (self->thread_running)
                continue;
            break;
        }
        
        /* Handle P2P connection in this thread (since we need to interact with user) */
        self->handle_p2p_connection(peer_fd);
    }
    
    return nullptr;
}

void ChatClient::handle_p2p_connection(int peer_fd) {
    std::string message;
    if (!NetworkUtils::recv_line(peer_fd, message)) {
        close(peer_fd);
        return;
    }
    
    std::istringstream iss(message);
    int msg_type;
    iss >> msg_type;
    
    switch (msg_type) {
        case CHAT_REQUEST: {
            std::string requester_name;
            iss >> requester_name;
            handle_chat_request(peer_fd, requester_name);
            break;
        }
        case CHAT_MSG: {
            /* This shouldn't happen in listen thread for the new protocol */
            /* But keep for backward compatibility or direct messages */
            std::string sender;
            iss >> sender;
            std::string content;
            std::getline(iss, content);
            if (!content.empty() && content[0] == ' ')
                content = content.substr(1);
            /* Store as direct message with "DM" as room name */
            message_store.add("DM", sender, content);
            UI::print_local_message("New message from " + sender);
            close(peer_fd);
            break;
        }
        default:
            close(peer_fd);
            break;
    }
}

void ChatClient::handle_chat_request(int peer_fd, const std::string& requester_name) {
    ClientState current = client_state.load();
    
    /* Auto-reject if busy */
    if (current == STATE_IN_CHAT || current == STATE_WAITING_ACCEPT || current == STATE_PENDING_REQUEST) {
        std::string response = std::to_string(CHAT_REJECT) + " busy";
        NetworkUtils::send_line(peer_fd, response);
        close(peer_fd);
        return;
    }
    
    /* Set pending request state */
    {
        std::lock_guard<std::mutex> lock(chat_mutex);
        pending_request_fd = peer_fd;
        pending_requester = requester_name;
        client_state = STATE_PENDING_REQUEST;
    }
    
    /* Notify user - they will see this on next prompt */
    UI::print_local_message("Chat request from " + requester_name + "! Type 'accept' or 'reject'");
}

void ChatClient::handle_chat_message(const std::string& message) {
    std::cout << "\r\033[K";  /* Clear current line */
    std::cout << Color::CYAN << chat_partner << Color::RESET << ": " << message << std::endl;
    UI::print_chat_prompt();
    std::cout.flush();
}

void ChatClient::handle_chat_end() {
    UI::print_warning(chat_partner + " has left the chat");
    exit_chat_mode();
}

/* ===================================
   Server Communication Commands
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
    if (listen_fd >= 0)
        close_listening_socket();
    
    if (!create_listening_socket(port)) {
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
        start_listen_thread();
    }
    else {
        int error_code;
        iss >> error_code;
        print_error_message(error_code);
        close_listening_socket();
    }
}

void ChatClient::cmd_logout() {
    if (logged_in_name.empty()) {
        UI::print_error("You must login first");
        return;
    }
    
    /* Cannot logout while in chat */
    if (client_state == STATE_IN_CHAT) {
        UI::print_error("Cannot logout while in a chat session. Type 'exit' first.");
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
        stop_listen_thread();
        close_listening_socket();
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

    /* Send quick P2P message (fire-and-forget) */
    int peer_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (peer_fd < 0) {
        UI::print_error("Failed to create socket");
        return;
    }

    sockaddr_in peer_addr{};
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_addr.s_addr = inet_addr(ip.c_str());
    peer_addr.sin_port = htons(port);

    if (connect(peer_fd, (sockaddr*)&peer_addr, sizeof(peer_addr)) < 0) {
        UI::print_error("Failed to connect to " + target_name);
        close(peer_fd);
        return;
    }

    /* Use CHAT_MSG with sender name for quick message */
    std::string msg = std::to_string(CHAT_MSG) + " " + logged_in_name + " " + message;
    if (NetworkUtils::send_line(peer_fd, msg))
        UI::print_success("Message sent to " + target_name);
    else
        UI::print_error("Failed to send message to " + target_name);

    close(peer_fd);
}

void ChatClient::cmd_messages(const std::string& room_name) {
    if (room_name.empty()) {
        UI::print_error("Usage: messages <room_name>");
        return;
    }
    
    auto messages = message_store.get_by_room(room_name);
    if (messages.empty()) {
        UI::print_info("No messages in room '" + room_name + "'");
        return;
    }
    
    UI::print_info("=== Messages in [" + room_name + "] ===");
    for (const auto& msg : messages)
        std::cout << "[" << msg.timestamp << "] " << msg.sender << ": " << msg.content << std::endl;
    UI::print_info("================================");
}

void ChatClient::cmd_quit() {
    /* Force exit chat mode if in chat */
    if (client_state == STATE_IN_CHAT) {
        /* Send CHAT_END only if socket is still valid */
        {
            std::lock_guard<std::mutex> lock(chat_mutex);
            if (chat_fd >= 0) {
                std::string msg = std::to_string(CHAT_END);
                NetworkUtils::send_line(chat_fd, msg);
            }
        }
        exit_chat_mode();
    }
    
    /* Stop listening thread */
    stop_listen_thread();
    
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
    /* Keep receiving until we get a non-GROUP_NOTIFY response */
    while (true) {
        if (!NetworkUtils::recv_line(server_fd, response)) {
            should_continue = false;
            return false;
        }
        
        /* Check if this is a GROUP_NOTIFY message */
        if (response.substr(0, 12) == "GROUP_NOTIFY") {
            std::istringstream iss(response);
            std::string notify_tag, room_name, sender;
            iss >> notify_tag >> room_name >> sender;
            
            std::string content;
            std::getline(iss, content);
            if (!content.empty() && content[0] == ' ')
                content = content.substr(1);
            
            /* Store message silently - user can view with 'messages <room>' */
            message_store.add(room_name, sender, content);
            continue;
        }
        
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