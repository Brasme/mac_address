cmake_minimum_required(VERSION 3.10.0)

add_subdirectory(arp)

project(mac LANGUAGES C CXX VERSION "1.0.0")

add_executable(${PROJECT_NAME} mac_main.cpp)
target_link_libraries(${PROJECT_NAME} arp)