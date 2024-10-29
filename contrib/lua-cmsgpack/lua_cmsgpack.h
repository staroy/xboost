#ifndef LUA_CMSGPACK_H
#define LUA_CMSGPACK_H

int mp_pack(lua_State *L, int offset, int limit, std::string& out);
//int mp_pack(lua_State *L, int offset, int limit, std::vector<char>& out);
int mp_unpack(lua_State *L);
int mp_unpack(lua_State *L, const char *s, size_t len);
int mp_unpack_one(lua_State *L, const char *s, size_t len, int offset);
int mp_unpack_limit(lua_State *L, const char *s, size_t len, int limit, int offset);

#endif