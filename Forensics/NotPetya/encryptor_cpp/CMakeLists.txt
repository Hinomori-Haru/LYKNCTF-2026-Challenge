cmake_minimum_required(VERSION 3.15)
project(encryptor CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(YUNEKO_DEV "Build dev: enable --key/--locate + diagnostic prints" OFF)

add_executable(encryptor main.cpp)
if (YUNEKO_DEV)
    target_compile_definitions(encryptor PRIVATE YUNEKO_DEV)
endif()
if (WIN32)
    target_link_libraries(encryptor bcrypt)
endif()
