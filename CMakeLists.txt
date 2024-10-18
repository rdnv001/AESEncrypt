cmake_minimum_required(VERSION 3.10)
project(FileEncryptor)

# Установить стандарт C++
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Добавить исполняемый файл
add_executable(file_encryptor main.cpp)

# Проверить наличие OpenSSL
find_package(OpenSSL REQUIRED)

# Линковка OpenSSL
target_link_libraries(file_encryptor OpenSSL::SSL OpenSSL::Crypto)

# Для Windows нужно добавить ws2_32 для работы сокетов, используемых в OpenSSL
if(WIN32)
    target_link_libraries(file_encryptor ws2_32)
endif()

