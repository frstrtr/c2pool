#pragma once
#include <exception>

class WebNotFound : public std::exception {
private:
    std::string message;

public:
    explicit WebNotFound(std::string msg) : message(std::move(msg)) {}
    explicit WebNotFound(const char* msg) : message(msg) {}

    const char* what() const noexcept override
    {
        return message.c_str();
    }
};

class WebServerError : public std::exception {
private:
    std::string message;

public:
    explicit WebServerError(std::string msg) : message(std::move(msg)) {}
    explicit WebServerError(const char* msg) : message(msg) {}

    const char* what() const noexcept override
    {
        return message.c_str();
    }
};

class WebBadRequest : public std::exception {
private:
    std::string message;

public:
    explicit WebBadRequest(std::string msg) : message(std::move(msg)) {}
    explicit WebBadRequest(const char* msg) : message(msg) {}

    const char* what() const noexcept override
    {
        return message.c_str();
    }
};

class WebInitError : public std::exception {
private:
    std::string message;

public:
    explicit WebInitError(std::string msg) : message(std::move(msg)) {}
    explicit WebInitError(const char* msg) : message(msg) {}

    const char* what() const noexcept override
    {
        return message.c_str();
    }
};