
# A simple CMake script for building the application.
cmake_minimum_required(VERSION 2.8)
project(create-x509)

# Our only dependency is OpenSSL
find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(create-x509 create-x509-cert.c)
target_link_libraries(create-x509 ${OPENSSL_LIBRARIES})

install(TARGETS create-x509 RUNTIME DESTINATION bin)
