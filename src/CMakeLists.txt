cmake_minimum_required(VERSION 3.0)
project (netsimul) 

set(CMAKE_CXX_COMPILER g++)
set(CMAKE_CXX_FLAGS "-std=c++11 -g")

# for header files
include_directories(include)

add_library(util SHARED Util.cpp)

add_subdirectory(test)

add_subdirectory(transport)
add_subdirectory(network)
add_subdirectory(link)

