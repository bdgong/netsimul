#set(CMAKE_CXX_FLAGS "-std=c++11 -g")

set(INJECTOR_SRCS injector.cpp)
set(SNIFFEX_SRCS sniffex.cpp)
add_executable(injector2 ${INJECTOR_SRCS})
add_executable(sniffex ${SNIFFEX_SRCS})
add_executable(DemoTimeClient DemoTimeClient.cpp)
add_executable(DemoTimeServer DemoTimeServer.cpp)
add_executable(DemoEchoClient DemoEchoClient.cpp)
add_executable(DemoEchoServer DemoEchoServer.cpp)

#message("LINK_SRCS: ${LINK_SRCS}")
#message("NEIGHBOR_SRCS: ${NEIGHBOR_SRCS}")

target_link_libraries(injector2 protosocket)
target_link_libraries(sniffex pcap)
target_link_libraries(DemoTimeClient socket)
target_link_libraries(DemoTimeServer socket)
target_link_libraries(DemoEchoClient socket)
target_link_libraries(DemoEchoServer socket)

