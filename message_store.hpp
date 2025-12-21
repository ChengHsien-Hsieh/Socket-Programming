#pragma once
#include <string>
#include <vector>
#include <pthread.h>
#include <ctime>

/* Message structure for P2P chat */
struct Message {
    std::string from;
    std::string content;
    std::string timestamp;
};

/* Thread-safe message storage */
class MessageStore {
private:
    std::vector<Message> messages;
    mutable pthread_mutex_t mutex;

public:
    MessageStore() {
        pthread_mutex_init(&mutex, nullptr);
    }
    
    ~MessageStore() {
        pthread_mutex_destroy(&mutex);
    }
    
    /* Add a new message with current timestamp */
    void add(const std::string& from, const std::string& content) {
        time_t now = time(nullptr);
        char timestamp[20];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
        
        pthread_mutex_lock(&mutex);
        messages.push_back({from, content, timestamp});
        pthread_mutex_unlock(&mutex);
    }
    
    /* Get all messages (copies for thread safety) */
    std::vector<Message> get_all() const {
        pthread_mutex_lock(&mutex);
        std::vector<Message> copy = messages;
        pthread_mutex_unlock(&mutex);
        return copy;
    }
    
    /* Check if message queue is empty */
    bool empty() const {
        pthread_mutex_lock(&mutex);
        bool result = messages.empty();
        pthread_mutex_unlock(&mutex);
        return result;
    }
    
    /* Clear all messages */
    void clear() {
        pthread_mutex_lock(&mutex);
        messages.clear();
        pthread_mutex_unlock(&mutex);
    }
};
