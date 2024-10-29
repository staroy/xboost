
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

link_directories(
  ${CMAKE_INSTALL_PREFIX}/lib
)

set(lldb_sources lldb.cpp)

set(lldb_include lldb.h)

monero_add_library(lldb
  SOURCES
    ${lldb_sources}
    ${lldb_headers})

target_link_libraries(lldb
  PUBLIC
    common
    leveldb)
