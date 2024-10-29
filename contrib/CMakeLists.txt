# Copyright (c) 2014-2022, The Monero Project
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

monero_enable_coverage()
add_subdirectory(epee)

#set(LUA_CMSGPACK_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lua-cmsgpack)
#set(LUA_CMSGPACK_BUILD_DIR ${CMAKE_BINARY_DIR}/lua-cmsgpack)

#  CONFIGURE_COMMAND mkdir -p ${LUA_CMSGPACK_BUILD_DIR} && cd ${LUA_CMSGPACK_BUILD_DIR} && cmake -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX} -DLUA_INCLUDE_DIR=${CMAKE_INSTALL_PREFIX}/include -DLUA_LIB_DIR=${CMAKE_INSTALL_PREFIX}/lib ${LUA_CMSGPACK_DIR}
#  CONFIGURE_COMMAND mkdir -p ${LUA_CMSGPACK_BUILD_DIR} && cd ${LUA_CMSGPACK_BUILD_DIR} && cmake -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX} -DLUA_INCLUDE_DIR=/usr/include/lua5.3 -DLUA_LIB_DIR=${CMAKE_INSTALL_PREFIX}/lib ${LUA_CMSGPACK_DIR}

#ExternalProject_Add(lua_cmsgpack_prj
#  CONFIGURE_COMMAND mkdir -p ${LUA_CMSGPACK_BUILD_DIR} && cd ${LUA_CMSGPACK_BUILD_DIR} && cmake -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX} -DLUA_INCLUDE_DIR=${CMAKE_INSTALL_PREFIX}/include/luajit-2.0 -DLUA_LIB_DIR=${CMAKE_INSTALL_PREFIX}/lib ${LUA_CMSGPACK_DIR}
#  BUILD_COMMAND cd ${LUA_CMSGPACK_BUILD_DIR} && make ${CMAKE_N_BUILDPROC} && make install
#  INSTALL_COMMAND ""
#  SOURCE_DIR ${LUA_CMSGPACK_DIR}
#  BINARY_DIR ${LUA_CMSGPACK_DIR}
#)

#add_dependencies(lua_cmsgpack_prj lua_prj)

set(AZMQ_DIR ${CMAKE_CURRENT_SOURCE_DIR}/azmq)
set(AZMQ_BUILD_DIR ${CMAKE_BINARY_DIR}/azmq)

if(${CMAKE_BUILD_TYPE} STREQUAL "Release")
    set(AZMQ_ZMQ_STATIC 1)
else()
    set(AZMQ_ZMQ_STATIC 0)
endif()

ExternalProject_Add(azmq_prj
  CONFIGURE_COMMAND mkdir -p ${AZMQ_BUILD_DIR} && cd ${AZMQ_BUILD_DIR} && cmake -DAZMQ_NO_TESTS=ON -DZMQ_STATIC=${AZMQ_ZMQ_STATIC} -DCMAKE_PREFIX_PATH=${CMAKE_INSTALL_PREFIX}/lib/pkgconfig -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX} ${AZMQ_DIR}
  BUILD_COMMAND cd ${AZMQ_BUILD_DIR} && make ${CMAKE_N_BUILDPROC} install
  INSTALL_COMMAND  ""
  SOURCE_DIR ${AZMQ_DIR}
  BINARY_DIR ${AZMQ_DIR}
)
