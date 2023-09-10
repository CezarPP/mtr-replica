cmake_minimum_required(VERSION 3.26)
project(mtr_replica)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)
find_package(Curses REQUIRED)

# Add the executable for the client
add_executable(client client.cpp Errors.h)
target_link_libraries(client PRIVATE ${CURSES_LIBRARIES})
target_link_libraries(client PRIVATE pthread)

# Add the executable for the server
add_executable(server server.cpp Errors.h)

