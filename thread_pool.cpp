#include "thread_pool.hpp"
#include "ui_utils.hpp"
#include <unistd.h>
#include <iostream>

ThreadPool::ThreadPool(int size, TaskHandler handler) : pool_size(size), task_handler(handler) {
    if (handler == nullptr)
        throw std::invalid_argument("TaskHandler cannot be nullptr");
    
    pthread_mutex_init(&client_fds_mutex, nullptr);
    pthread_cond_init(&client_fds_cond, nullptr);
    workers = new pthread_t[pool_size];
    for (int i = 0; i < pool_size; i++) {
        pthread_create(&workers[i], nullptr, worker_thread, this);
        pthread_detach(workers[i]);  // Detach thread to avoid memory leaks
    }

    ChatUI::print_server_status("Thread pool initialized with " + std::to_string(pool_size) + " workers");
}

ThreadPool::~ThreadPool() {
    delete[] workers;
    pthread_mutex_destroy(&client_fds_mutex);
    pthread_cond_destroy(&client_fds_cond);
}

void ThreadPool::submit(int client_fd) {
    pthread_mutex_lock(&client_fds_mutex);
    client_fds.push(client_fd);
    pthread_cond_signal(&client_fds_cond);  // Signal one worker
    pthread_mutex_unlock(&client_fds_mutex);
}

void* ThreadPool::worker_thread(void* arg) {
    ThreadPool* pool = (ThreadPool*)arg;
    while (true) {
        pthread_mutex_lock(&pool->client_fds_mutex);
        while (pool->client_fds.empty() && !pool->stop)
            pthread_cond_wait(&pool->client_fds_cond, &pool->client_fds_mutex);

        if (pool->stop) {
            pthread_mutex_unlock(&pool->client_fds_mutex);
            break;
        }

        int client_fd = pool->client_fds.front();
        pool->client_fds.pop();
        pthread_mutex_unlock(&pool->client_fds_mutex);
        pool->task_handler(client_fd, &pool->stop);
    }

    pthread_exit(nullptr);
}

void ThreadPool::shutdown() {
    stop = true;
    pthread_mutex_lock(&client_fds_mutex);
    if (client_fds.size() > 0)
        ChatUI::print_warning("Closing " + std::to_string(client_fds.size()) + " pending connections...");
    while (!client_fds.empty()) {
        close(client_fds.front());
        client_fds.pop();
    }
    pthread_cond_broadcast(&client_fds_cond);  // Broadcast all workers waiting for tasks
    pthread_mutex_unlock(&client_fds_mutex);
}