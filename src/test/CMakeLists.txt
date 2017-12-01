set(CMAKE_CXX_FLAGS "-std=c++11 -g")

add_executable(injector2 injector.cpp)

target_link_libraries(injector2 pcap)
