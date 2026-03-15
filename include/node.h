#pragma once
#include <cstdint>

class Node {
public:
    explicit Node(uint16_t id) : id_(id) {}
    uint16_t id() const { return id_; }

private:
    uint16_t id_;
};
