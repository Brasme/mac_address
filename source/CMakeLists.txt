cmake_minimum_required(VERSION 3.10.0)

add_subdirectory(arp)
add_subdirectory(mac)

project(mac_tool LANGUAGES C CXX VERSION "1.0.0")

add_executable(${PROJECT_NAME} mac_main.cpp)
target_link_libraries(${PROJECT_NAME} arp mac)