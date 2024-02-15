cmake_minimum_required(VERSION 3.10.0)

project(mac LANGUAGES C CXX VERSION "1.0.0")

add_library(${PROJECT_NAME} get_mac.c include/mac/get_mac.h)

target_include_directories(${PROJECT_NAME} PUBLIC 
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:include>" 
)