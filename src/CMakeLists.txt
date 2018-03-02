cmake_minimum_required(VERSION 3.0)
project (netsimul) 

set(CMAKE_CXX_COMPILER g++)
set(CMAKE_CXX_FLAGS "-std=c++11 -g -O0")

# for header files
include_directories(include)

add_library(util SHARED Util.cpp CheckSum.cpp)
add_library(socket SHARED Socket.cpp)
add_library(protosocket SHARED ProtoSocket.cpp
    ${LINK_SRCS}
    ${NETWORK_SRCS}
    ${TRANSPORT_SRCS}
    )

add_subdirectory(test)

add_subdirectory(transport)
add_subdirectory(network)
add_subdirectory(link)

add_executable(Protocol Protocol.cpp)

target_link_libraries(protosocket util pcap pthread)
target_link_libraries(Protocol protosocket)

