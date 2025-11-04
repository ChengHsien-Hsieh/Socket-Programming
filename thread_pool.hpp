// thread_pool.hpp
#pragma once
#include <pthread.h>
#include <queue>
#include <atomic>

// Forward declaration of global variable from server.cpp
// extern std::atomic<bool> server_running;

class ThreadPool {
private:
    std::queue<int> task_queue;       // 待處理的 client_fd
    pthread_mutex_t queue_mutex;      // 保護 queue
    pthread_cond_t queue_cond;        // 條件變數：通知有新任務
    
    pthread_t* workers;               // Worker threads 陣列
    int pool_size;                    // Pool 大小
    bool shutdown;                    // 是否正在關閉
    
    static void* worker_thread(void* arg);  // Worker 函數
    
public:
    ThreadPool(int size);
    ~ThreadPool();
    
    void submit(int client_fd);       // 提交任務
    void stop();                      // 停止 pool
};