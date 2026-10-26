cmake_minimum_required(VERSION 3.16)
project(saves_sdk CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(CURL REQUIRED)

add_library(saves_sdk STATIC src/client.cpp src/push_pull.cpp)
target_include_directories(saves_sdk PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/third_party>
  $<INSTALL_INTERFACE:include>)
target_link_libraries(saves_sdk PUBLIC CURL::libcurl)
target_compile_options(saves_sdk PRIVATE -Wall -Wextra -Wpedantic)

install(TARGETS saves_sdk EXPORT saves_sdk ARCHIVE DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)
install(EXPORT saves_sdk FILE saves_sdk-config.cmake NAMESPACE saves:: DESTINATION lib/cmake/saves_sdk)

enable_testing()
add_executable(test_offline tests/test_offline.cpp)
target_include_directories(test_offline PRIVATE include third_party src)
target_link_libraries(test_offline PRIVATE saves_sdk)
add_test(NAME offline COMMAND test_offline)

add_executable(test_integration tests/test_integration.cpp)
target_include_directories(test_integration PRIVATE include third_party src)
target_link_libraries(test_integration PRIVATE saves_sdk)
