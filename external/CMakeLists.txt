# Copyright (c) 2014-2019, The Monero Project
# 
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
# 
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
# Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers


# This is broken up into two parts: first we check for miniupnp, compile it if we can't
# find it, and thereafter we check for libunbound, and compile it if we can't find it.
# We always compile if we are building statically to reduce static dependency issues...
# ...except for FreeBSD, because FreeBSD is a special case that doesn't play well with
# others.

include(ExternalProject)

find_package(Miniupnpc REQUIRED)

message(STATUS "Using in-tree miniupnpc")
set(UPNPC_NO_INSTALL TRUE CACHE BOOL "Disable miniupnp installation" FORCE)
add_subdirectory(miniupnp/miniupnpc)
set_property(TARGET libminiupnpc-static PROPERTY FOLDER "external")
set_property(TARGET libminiupnpc-static PROPERTY POSITION_INDEPENDENT_CODE ON)
if(MSVC)
  set_property(TARGET libminiupnpc-static APPEND_STRING PROPERTY COMPILE_FLAGS " -wd4244 -wd4267")
elseif(NOT MSVC)
  set_property(TARGET libminiupnpc-static APPEND_STRING PROPERTY COMPILE_FLAGS " -Wno-undef -Wno-unused-result -Wno-unused-value")
endif()
if(CMAKE_SYSTEM_NAME MATCHES "NetBSD")
	set_property(TARGET libminiupnpc-static APPEND_STRING PROPERTY COMPILE_FLAGS " -D_NETBSD_SOURCE")
endif()

set(UPNP_LIBRARIES "libminiupnpc-static" PARENT_SCOPE)

find_package(Unbound)

if(NOT UNBOUND_INCLUDE_DIR)
  die("Could not find libunbound")
else()
  message(STATUS "Found libunbound include (unbound.h) in ${UNBOUND_INCLUDE_DIR}")
  if(UNBOUND_LIBRARIES)
    message(STATUS "Found libunbound library")
  else()
    die("Found libunbound includes, but could not find libunbound library. Please make sure you have installed libunbound or libunbound-dev or the equivalent")
  endif()
endif()

add_subdirectory(db_drivers)
add_subdirectory(easylogging++)
add_subdirectory(qrcodegen)
add_subdirectory(randomx EXCLUDE_FROM_ALL)
add_subdirectory(msgpack-cxx)
add_subdirectory(sol2)

set(LUAJIT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/LuaJIT)

if(${CMAKE_BUILD_TYPE} STREQUAL "Release")
    set(LUAJIT_OPT "-fPIC -O2 -fomit-frame-pointer")
    set(LUAJIT_DEBUG "-g0")
    set(LUAJIT_BUILDMODE static)
else()
    set(LUAJIT_OPT "-fPIC -O0 -fomit-frame-pointer")
    set(LUAJIT_DEBUG "-g3")
    set(LUAJIT_BUILDMODE dynamic)
endif()

set(LUAJIT_BUILD_DIR ${CMAKE_BINARY_DIR}/LuaJIT)

ExternalProject_Add(lua_prj
  CONFIGURE_COMMAND cp -R ${LUAJIT_DIR} ${CMAKE_BINARY_DIR}
  BUILD_COMMAND cd ${LUAJIT_BUILD_DIR} && make BUILDMODE=${LUAJIT_BUILDMODE} CCOPT=${LUAJIT_OPT} CCDEBUG=${LUAJIT_DEBUG} ${CMAKE_N_BUILDPROC} PREFIX=${CMAKE_INSTALL_PREFIX} install
  INSTALL_COMMAND  ""
  SOURCE_DIR ${LUAJIT_DIR}
  BINARY_DIR ${LUAJIT_DIR}
)

set(ZYRE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/zyre)
set(ZYRE_BUILD_DIR ${CMAKE_BINARY_DIR}/zyre)

if(${CMAKE_BUILD_TYPE} STREQUAL "Release")
    set(ZYRE_CFLAGS "-g0 -O2 -DZMQ_CURVE")
    set(ZYRE_STATIC ON)
    set(ZYRE_SHARED OFF)
    #set(ZYRE_LDFLAGS "-lstdc++ -lpthread -luuid -L${CMAKE_INSTALL_PREFIX}/lib -lzmq -lsodium")
else()
    set(ZYRE_CFLAGS "-g3 -O0 -DZMQ_CURVE")
    set(ZYRE_STATIC OFF)
    set(ZYRE_SHARED ON)
endif()

ExternalProject_Add(zyre_prj
  CONFIGURE_COMMAND mkdir -p ${ZYRE_BUILD_DIR} && cd ${ZYRE_BUILD_DIR} && cmake -DENABLE_DRAFTS=ON -DZYRE_BUILD_STATIC=${ZYRE_STATIC} -DZYRE_BUILD_SHARED=${ZYRE_SHARED} -DOPTIONAL_LIBRARIES_STATIC=${ZYRE_LDFLAGS} -DCMAKE_C_FLAGS=${ZYRE_CFLAGS} -DCMAKE_PREFIX_PATH=${CMAKE_INSTALL_PREFIX}/lib/pkgconfig -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX} ${ZYRE_DIR}
  BUILD_COMMAND cd ${ZYRE_BUILD_DIR} && make ${CMAKE_N_BUILDPROC} install
  INSTALL_COMMAND  ""
  SOURCE_DIR ${ZYRE_DIR}
  BINARY_DIR ${ZYRE_DIR}
)
