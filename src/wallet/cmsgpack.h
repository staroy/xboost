#ifndef LUA_CMSGPACK_H
#define LUA_CMSGPACK_H

int xpack(lua_State *L, int offset, int limit, std::string& out);
int xunpack(lua_State *L, const char *s, size_t len);

#endif