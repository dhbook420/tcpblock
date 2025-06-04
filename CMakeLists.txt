cmake_minimum_required(VERSION 3.10)
project(tcp-block)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)



add_executable(tcp-block
        main.cpp
        mac.h
        ip.h
        ethhdr.h
        iphdr.h)

target_link_libraries(tcp-block pcap)