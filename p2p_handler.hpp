#pragma once
#include "network_utils.hpp"
#include "message_store.hpp"
#include "ui_utils.hpp"
#include <string>
#include <atomic>
#include <mutex>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sstream>

#define BACKLOG 10

/* Handles P2P connections and messaging */
class P2PHandler {
private:
    int listen_fd;
    int listen_port;
    pthread_t listen_thread;
    std::atomic<bool> thread_running;
    MessageStore& message_store;  // Reference to shared message store

public:
    explicit P2PHandler(MessageStore& store) 
        : listen_fd(-1), listen_port(0), listen_thread(0), 
          thread_running(false), message_store(store) {}
    
    ~P2PHandler() {
        stop();
    }
    
    /* Create listening socket on specified port
     * Returns true on success, false if port is unavailable */
    bool create_socket(int port) {
        listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd < 0)
            NetworkUtils::ERR_EXIT("socket");
        
        int opt = 1;
        if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
            NetworkUtils::ERR_EXIT("setsockopt");
        
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);
        
        if (bind(listen_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
            close(listen_fd);
            listen_fd = -1;
            return false;
        }
        
        if (listen(listen_fd, BACKLOG) < 0)
            NetworkUtils::ERR_EXIT("listen");
        
        listen_port = port;
        // UI::print_local_message("P2P listening socket created on port " + std::to_string(port));
        return true;
    }
    
    /* Close listening socket */
    void close_socket() {
        if (listen_fd < 0)
            return;
        // UI::print_local_message("Closing P2P listening socket on port " + std::to_string(listen_port));
        close(listen_fd);
        listen_fd = -1;
        listen_port = 0;
    }
    
    /* Start accepting incoming P2P connections */
    void start() {
        if (thread_running)
            return;
        
        thread_running = true;
        if (pthread_create(&listen_thread, nullptr, thread_func, this) != 0) {
            UI::print_error("Failed to create listening thread");
            thread_running = false;
        }
    }
    
    /* Stop accepting connections and cleanup */
    void stop() {
        if (!thread_running)
            return;
        
        thread_running = false;
        
        if (listen_fd >= 0) {
            shutdown(listen_fd, SHUT_RDWR);
            close(listen_fd);
            listen_fd = -1;
            listen_port = 0;
        }
        
        if (listen_thread != 0) {
            pthread_join(listen_thread, nullptr);
            listen_thread = 0;
        }
    }
    
    /* Send a P2P message to target at ip:port */
    static bool send_message(const std::string& ip, int port, 
                             const std::string& sender_name, const std::string& message) {
        int peer_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (peer_fd < 0)
            NetworkUtils::ERR_EXIT("socket");
        
        sockaddr_in peer_addr{};
        peer_addr.sin_family = AF_INET;
        peer_addr.sin_addr.s_addr = inet_addr(ip.c_str());
        peer_addr.sin_port = htons(port);
        
        if (connect(peer_fd, (sockaddr*)&peer_addr, sizeof(peer_addr)) < 0) {
            close(peer_fd);
            return false;
        }
        
        std::string full_message = sender_name + " " + message;
        bool success = NetworkUtils::send_line(peer_fd, full_message);
        close(peer_fd);
        
        return success;
    }
    
    bool is_running() const { return thread_running; }
    bool has_socket() const { return listen_fd >= 0; }

private:
    /* Arguments for connection worker thread */
    struct ConnectionArgs {
        P2PHandler* handler;
        int fd;
    };
    
    /* Thread function for accepting connections (Concurrent Server) */
    static void* thread_func(void* arg) {
        P2PHandler* handler = static_cast<P2PHandler*>(arg);
        
        while (handler->thread_running && handler->listen_fd >= 0) {
            sockaddr_in peer_addr{};
            socklen_t addr_len = sizeof(peer_addr);
            int peer_fd = accept(handler->listen_fd, (sockaddr*)&peer_addr, &addr_len);
            
            if (peer_fd < 0) {
                if (!handler->thread_running)
                    break;
                continue;
            }
            
            /* Fire-and-forget: spawn a detached thread to handle this connection */
            pthread_t worker_thread;
            ConnectionArgs* args = new ConnectionArgs{handler, peer_fd};
            if (pthread_create(&worker_thread, nullptr, connection_worker, args) == 0) {
                pthread_detach(worker_thread);  // Let it clean up itself
            } else {
                /* Failed to create thread, cleanup and continue */
                close(peer_fd);
                delete args;
            }
        }
        
        return nullptr;
    }
    
    /* Worker thread function for handling a single connection */
    static void* connection_worker(void* arg) {
        ConnectionArgs* args = static_cast<ConnectionArgs*>(arg);
        args->handler->handle_connection(args->fd);
        delete args;  // Cleanup allocated memory
        return nullptr;
    }
    
    /* Handle incoming P2P connection */
    void handle_connection(int peer_fd) {
        std::string line;
        if (!NetworkUtils::recv_line(peer_fd, line)) {
            close(peer_fd);
            return;
        }
        close(peer_fd);
        
        if (line.empty())
            return;
        
        std::istringstream iss(line);
        std::string sender;
        iss >> sender;
        
        std::string content;
        std::getline(iss, content);
        if (!content.empty() && content[0] == ' ')
            content = content.substr(1);
        
        message_store.add(sender, content);
        
        /* UI: clear current line, print message, restore prompt */
        {
            std::lock_guard<std::mutex> lock(UI::get_cout_mutex());
            std::cout << "\r\033[K";  // Carriage return + clear line
            UI::print_local_message("New message from " + sender);
            UI::print_prompt();
            std::cout << std::flush;
        }
    }
};
