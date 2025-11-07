#pragma once
#include <pthread.h>
#include <queue>
#include <atomic>

typedef void (*TaskHandler)(int client_fd, std::atomic<bool>* shutdown_flag);

class ThreadPool {
private:
    std::atomic<bool> stop = false;
    int pool_size;
    pthread_t* workers;
    TaskHandler task_handler;
    static void* worker_thread(void* arg);

    std::queue<int> client_fds;
    pthread_mutex_t client_fds_mutex;
    pthread_cond_t client_fds_cond;
    
public:
    ThreadPool(int size, TaskHandler handler);
    ~ThreadPool();

    void submit(int client_fd);
    void shutdown();
};