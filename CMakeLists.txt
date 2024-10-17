cmake_minimum_required(VERSION 3.10)
project(FileEncryptor)

# Установите стандарт C++
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Добавляем исполняемый файл
add_executable(file_encryptor main.cpp)

# Проверяем наличие OpenSSL
find_package(OpenSSL REQUIRED)

# Линкуем OpenSSL
target_link_libraries(file_encryptor OpenSSL::SSL OpenSSL::Crypto)

# Для Windows нужно добавить ws2_32 для работы сокетов, используемых в OpenSSL
if(WIN32)
    target_link_libraries(file_encryptor ws2_32)
endif()

