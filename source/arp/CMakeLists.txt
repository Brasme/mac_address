cmake_minimum_required(VERSION 3.10.0)

project(arp LANGUAGES C CXX VERSION "1.0.0")

add_library(${PROJECT_NAME} arp_mac.c include/arp/arp_mac.h)

target_include_directories(${PROJECT_NAME} PUBLIC 
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:include>" 
)