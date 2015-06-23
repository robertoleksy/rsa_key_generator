project(rsa_key_generator)
set(CMAKE_CXX_FLAGS "-std=c++11")

add_executable(rsa_key_generator main.cpp)
target_link_libraries(rsa_key_generator crypto cryptopp)