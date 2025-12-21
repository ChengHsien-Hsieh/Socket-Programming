#ifndef UI_UTILS_HPP
#define UI_UTILS_HPP

#include <string>
#include <iostream>
#include <sstream>
#include <mutex>

/* Global mutex for thread-safe console output */
namespace UI {
    inline std::mutex& get_cout_mutex() {
        static std::mutex cout_mutex;
        return cout_mutex;
    }
}

/* ANSI Color Codes */
namespace Color {
    // Text colors
    const std::string RESET   = "\033[0m";
    const std::string BOLD    = "\033[1m";
    const std::string DIM     = "\033[2m";
    const std::string UNDERLINE = "\033[4m";
    
    // Foreground colors
    const std::string BLACK   = "\033[30m";
    const std::string RED     = "\033[31m";
    const std::string GREEN   = "\033[32m";
    const std::string YELLOW  = "\033[33m";
    const std::string BLUE    = "\033[34m";
    const std::string MAGENTA = "\033[35m";
    const std::string CYAN    = "\033[36m";
    const std::string WHITE   = "\033[37m";
    
    // Bright foreground colors
    const std::string BRIGHT_BLACK   = "\033[90m";
    const std::string BRIGHT_RED     = "\033[91m";
    const std::string BRIGHT_GREEN   = "\033[92m";
    const std::string BRIGHT_YELLOW  = "\033[93m";
    const std::string BRIGHT_BLUE    = "\033[94m";
    const std::string BRIGHT_MAGENTA = "\033[95m";
    const std::string BRIGHT_CYAN    = "\033[96m";
    const std::string BRIGHT_WHITE   = "\033[97m";
}

/* UI Helper Functions */
namespace UI {
    // Box drawing characters
    const std::string BOX_H = "─";
    const std::string BOX_V = "│";
    const std::string BOX_TL = "┌";
    const std::string BOX_TR = "┐";
    const std::string BOX_BL = "└";
    const std::string BOX_BR = "┘";
    
    // Print a horizontal line
    inline void print_line(int width = 60, const std::string& color = Color::BRIGHT_BLACK) {
        std::cout << color;
        for (int i = 0; i < width; i++) std::cout << BOX_H;
        std::cout << Color::RESET << std::endl;
    }
    
    // Print a boxed message
    inline void print_box(const std::string& message, const std::string& color = Color::CYAN) {
        int width = 60;
        std::cout << color << BOX_TL;
        for (int i = 0; i < width - 2; i++) std::cout << BOX_H;
        std::cout << BOX_TR << Color::RESET << std::endl;
        
        std::cout << color << BOX_V << Color::RESET << " " 
                  << Color::BOLD << message << Color::RESET;
        int padding = width - message.length() - 4;
        for (int i = 0; i < padding; i++) std::cout << " ";
        std::cout << color << BOX_V << Color::RESET << std::endl;
        
        std::cout << color << BOX_BL;
        for (int i = 0; i < width - 2; i++) std::cout << BOX_H;
        std::cout << BOX_BR << Color::RESET << std::endl;
    }
    
    // Message types for client
    inline void print_server_message(const std::string& msg) {
        std::cout << Color::BRIGHT_CYAN << "◆ Server: " << Color::RESET 
                  << Color::CYAN << msg << Color::RESET << std::endl;
    }
    
    inline void print_local_message(const std::string& msg) {
        std::cout << Color::BRIGHT_BLACK << "▸ " << Color::RESET 
                  << Color::WHITE << msg << Color::RESET << std::endl;
    }
    
    inline void print_success(const std::string& msg) {
        std::cout << Color::GREEN << "✓ " << msg << Color::RESET << std::endl;
    }
    
    inline void print_error(const std::string& msg) {
        std::cout << Color::RED << "✗ Error: " << msg << Color::RESET << std::endl;
    }
    
    inline void print_warning(const std::string& msg) {
        std::cout << Color::YELLOW << "⚠ Warning: " << msg << Color::RESET << std::endl;
    }
    
    inline void print_info(const std::string& msg) {
        std::cout << Color::BLUE << "ⓘ " << msg << Color::RESET << std::endl;
    }
    
    inline void print_prompt() {
        std::cout << Color::BRIGHT_MAGENTA << "❯ " << Color::RESET;
    }
    
    // Chat mode prompt (simple arrow, no brackets)
    inline void print_chat_prompt() {
        std::cout << Color::BRIGHT_GREEN << "» " << Color::RESET;
    }
    
    // Server specific messages
    inline void print_client_connected(const std::string& addr, int port) {
        std::cout << Color::BRIGHT_GREEN << "⬢ New client: " << Color::RESET 
                  << Color::GREEN << addr << ":" << port << Color::RESET << std::endl;
    }
    
    inline void print_client_disconnected(int fd) {
        std::cout << Color::BRIGHT_BLACK << "⬡ Connection closed: " << Color::RESET 
                  << Color::WHITE << "fd " << fd << Color::RESET << std::endl;
    }
    
    inline void print_server_status(const std::string& msg) {
        std::cout << Color::BRIGHT_BLUE << "● " << msg << Color::RESET << std::endl;
    }
    
    // Header/Banner
    inline void print_banner(const std::string& title) {
        int width = 60;
        std::cout << std::endl;
        std::cout << Color::BRIGHT_CYAN << BOX_TL;
        for (int i = 0; i < width - 2; i++) std::cout << BOX_H;
        std::cout << BOX_TR << Color::RESET << std::endl;
        
        int padding_left = (width - title.length() - 2) / 2;
        int padding_right = width - title.length() - 2 - padding_left;
        
        std::cout << Color::BRIGHT_CYAN << BOX_V << Color::RESET;
        for (int i = 0; i < padding_left; i++) std::cout << " ";
        std::cout << Color::BOLD << Color::BRIGHT_WHITE << title << Color::RESET;
        for (int i = 0; i < padding_right; i++) std::cout << " ";
        std::cout << Color::BRIGHT_CYAN << BOX_V << Color::RESET << std::endl;
        
        std::cout << Color::BRIGHT_CYAN << BOX_BL;
        for (int i = 0; i < width - 2; i++) std::cout << BOX_H;
        std::cout << BOX_BR << Color::RESET << std::endl;
        std::cout << std::endl;
    }
}

#endif // UI_UTILS_HPP
