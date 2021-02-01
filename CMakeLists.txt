cmake_minimum_required(VERSION 3.16)
project(network)

set(CMAKE_CXX_STANDARD 20)
option(NETWORK_BUILD_TESTS "" ON)
option(NETWORK_BUILD_EXAMPLES "" ON)

if(NETWORK_BUILD_TESTS)
    # Download and unpack googletest at configure time
    configure_file(CMakeLists.txt.in googletest-download/CMakeLists.txt)
    execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download )
    if(result)
        message(FATAL_ERROR "CMake step for googletest failed: ${result}")
    endif()
    execute_process(COMMAND ${CMAKE_COMMAND} --build .
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download )
    if(result)
        message(FATAL_ERROR "Build step for googletest failed: ${result}")
    endif()

    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

    # Import google test sub-directory
    add_subdirectory(${CMAKE_CURRENT_BINARY_DIR}/googletest-src
            ${CMAKE_CURRENT_BINARY_DIR}/googletest-build
            EXCLUDE_FROM_ALL)
endif()

file(GLOB TESTS tests/*.h tests/*.cpp)
include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include /usr/include)

if(UNIX)
    add_definitions(-DLINUX)
endif(UNIX)

if(WIN32)
    add_definitions(-DWINDOWS)
endif(WIN32)

if(LINUX)
    set(COMPILE_FLAGS "-msse3 -maes")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${COMPILE_FLAGS}")
endif()

if(NETWORK_BUILD_TESTS)
    add_executable(network-test ${TESTS})
    enable_testing()
    add_test(NAME network_test COMMAND network_test)
    target_link_libraries(network-test gtest_main)
    if(WIN32)
        target_link_libraries(network-test ws2_32)
    endif()
endif()

if(NETWORK_BUILD_EXAMPLES)
    add_executable(http-test examples/http_example.cpp)
    add_executable(https-test examples/https_example.cpp)
    target_link_libraries(http-test gtest_main)
    target_link_libraries(https-test gtest_main)

    if(WIN32)
        target_link_libraries(http-test ws2_32)
        target_link_libraries(https-test ws2_32)
    endif()
endif()


