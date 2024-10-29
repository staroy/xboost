cmake_minimum_required(VERSION 3.2)

project(cmsgpack)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -std=c++14")

include_directories(${LUA_INCLUDE_DIR})
link_directories(${LUA_LIB_DIR})

add_library(cmsgpack_static STATIC lua_cmsgpack.cpp)
add_library(cmsgpack SHARED lua_cmsgpack.cpp)

set_target_properties(cmsgpack_static PROPERTIES
    PUBLIC_HEADER "lua_cmsgpack.h"
    OUTPUT_NAME cmsgpack
)

set_target_properties(cmsgpack PROPERTIES PREFIX "")
target_link_libraries(cmsgpack luajit-5.1)

#install(TARGETS cmsgpack cmsgpack_static
install(TARGETS cmsgpack_static
 RUNTIME DESTINATION   bin
 PUBLIC_HEADER DESTINATION include
 LIBRARY DESTINATION   lib
 PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
             GROUP_EXECUTE GROUP_READ
 ARCHIVE DESTINATION lib
)

install(TARGETS cmsgpack
 RUNTIME DESTINATION   bin
 PUBLIC_HEADER DESTINATION include
 LIBRARY DESTINATION   lib
 PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
             GROUP_EXECUTE GROUP_READ
 ARCHIVE DESTINATION lib
)
