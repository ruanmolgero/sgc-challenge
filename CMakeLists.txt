# Versão mínima do CMake
cmake_minimum_required(VERSION 3.10)
project("challenge")

message(STATUS "**************** Building challenge ****************")

# Configurações globais do projeto
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Adicionar o executável
add_executable(${PROJECT_NAME} challenge.cpp)

# Diretórios de inclusão
include_directories(
                    # libcryptosec include
                    "/usr/local/ssl/include" 
                    "/usr/local/include/libcryptosec/" 
                    "/opt/libp11//include/"
                    # poppler include
                    # "/usr/include/poppler/glib/"
                    # # glib-2.0 include
                    # "/usr/include/glib-2.0/"
                    # "/usr/lib/x86_64-linux-gnu/glib-2.0/include/"
                    # "/usr/include/cairo/"
                    )

# Bibliotecas a serem vinculadas
link_libraries(crypto)
link_directories("/usr/local/ssl/lib")

# Opções de compilação
target_compile_options(${PROJECT_NAME} PRIVATE -O0 -Wall -c -pthread)

# Bibliotecas a serem vinculadas com o executável
#################################################
# libcryptosec
target_link_libraries(${PROJECT_NAME} "/usr/local/lib64/libcryptosec.so")
# # poppler link
# target_link_libraries(${PROJECT_NAME} poppler-glib)
# target_link_libraries(${PROJECT_NAME} glib-2.0 gobject-2.0)
