// thread_pool.cpp
#include "thread_pool.hpp"
#include "server.hpp"
#include <unistd.h>
#include <iostream>

ThreadPool::ThreadPool(int size) : pool_size(size), shutdown(false) {
    pthread_mutex_init(&queue_mutex, nullptr);
    pthread_cond_init(&queue_cond, nullptr);
    
    workers = new pthread_t[pool_size];
    for (int i = 0; i < pool_size; i++)
        pthread_create(&workers[i], nullptr, worker_thread, this);

    std::cout << "Thread pool initialized with " << pool_size << " workers\n";
}

ThreadPool::~ThreadPool() {
    // stop();
    delete[] workers;
    pthread_mutex_destroy(&queue_mutex);
    pthread_cond_destroy(&queue_cond);
}

void ThreadPool::submit(int client_fd) {
    pthread_mutex_lock(&queue_mutex);
    
    task_queue.push(client_fd);
    pthread_cond_signal(&queue_cond);  // Signal a worker
    pthread_mutex_unlock(&queue_mutex);
}

void ThreadPool::stop() {
    pthread_mutex_lock(&queue_mutex);
    shutdown = true;
    std::cout << "Closing " << task_queue.size() << " pending connections...\n";
    while (!task_queue.empty()) {
        close(task_queue.front());
        task_queue.pop();
    }
    pthread_cond_broadcast(&queue_cond);  // Broadcast all workers
    pthread_mutex_unlock(&queue_mutex);

    /* Wait for all workers to finish */
    for (int i = 0; i < pool_size; i++)
        pthread_join(workers[i], nullptr);
}

void* ThreadPool::worker_thread(void* arg) {
    ThreadPool* pool = (ThreadPool*)arg;
    
    while (true) {
        pthread_mutex_lock(&pool->queue_mutex);

        /* Wait for a task and shutdown signal */
        while (pool->task_queue.empty() && !pool->shutdown)
            pthread_cond_wait(&pool->queue_cond, &pool->queue_mutex);

        /* Check if we should shutdown */
        if (pool->shutdown) {
            pthread_mutex_unlock(&pool->queue_mutex);
            break;
        }

        /* Retrieve a task */
        int client_fd = pool->task_queue.front();
        pool->task_queue.pop();
        
        pthread_mutex_unlock(&pool->queue_mutex);

        /* Handle the client */
        ClientConnection conn(client_fd);
        std::string command;
        while (conn.recv_line(command) && !pool->shutdown)
            conn.handle_command(command);
        std::cout << "Closing connection for client " << client_fd << "\n";
    }

    pthread_exit(nullptr);
}