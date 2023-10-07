# Versão mínima do CMake
cmake_minimum_required(VERSION 3.10)
project("challenge")

message(STATUS "**************** Building challenge ****************")

# Configurações globais do projeto
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_BUILD_TYPE Debug)

# Adicionar o executável
add_executable(${PROJECT_NAME} challenge.cpp)

# Diretórios de inclusão
include_directories(
                    # libcryptosec includes
                    "/usr/local/ssl/include" 
                    "/usr/local/include/libcryptosec/" 
                    "/opt/libp11//include/"
                    )

# Opções de compilação
target_compile_options(${PROJECT_NAME} PRIVATE -O0 -Wall -c -pthread)

# Bibliotecas a serem vinculadas com o executável
#################################################
# libcryptosec
target_link_libraries(${PROJECT_NAME} "/usr/local/lib64/libcryptosec.so")
target_link_libraries(${PROJECT_NAME} crypto)

# Bibliotecas a serem vinculadas
# link_libraries(crypto)
link_directories("/usr/local/ssl/lib")
