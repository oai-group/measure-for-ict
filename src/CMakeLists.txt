aux_source_directory (${PROJECT_SOURCE_DIR}/src SRC_LIST)

include_directories (${PROJECT_SOURCE_DIR}/include)

add_executable (main ${SRC_LIST})

set (EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

set (PROJECT_BINARY_DIR ${PROJECT_SOURCE_DIR}/build)

target_link_libraries(main ${PROJECT_SOURCE_DIR}/lib/libmysqlclient.so -lpthread -lm)