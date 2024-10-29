#ifndef LLDB_DATABASE_H
#define LLDB_DATABASE_H

#include "leveldb/db.h"
#include "leveldb/iterator.h"
#include "leveldb/write_batch.h"

#include "wallet/wallet_errors.h"

#include <string>
#include <map>
#include <memory>
#include <vector>
#include <mutex>

#include "crypto/hash.h"

namespace lldb {

  struct InVal
  {
     const char *data; size_t size;

     InVal(const crypto::hash& h) : data(h.data), size(crypto::HASH_SIZE) {}
     InVal(const char *d, size_t s) : data(d), size(s) {}
     InVal(const char *s) { data = s; size = strlen(s); }
     template<typename T>
     InVal(const T& s) : data((const char *)&s), size(sizeof(s)) {}
  };

  struct OutVal
  {
     std::string data;

     OutVal() {}

     OutVal(const crypto::hash& h) : data((const char *)&h.data, ((const char *)&h.data)+crypto::HASH_SIZE) {}

     template<typename T>
     OutVal(const T& v) : data((const char *)&v, ((const char *)&v)+sizeof(T)) {}

     template<typename T>
     const T& get() {
       THROW_WALLET_EXCEPTION_IF(data.size() != sizeof(T),
         tools::error::wallet_internal_error, "OutVal invalid size of data, expected: " + std::to_string(sizeof(T)) + " but: " + std::to_string(data.size()));
       return *((T*)data.data());
     }

     OutVal& operator += (const crypto::hash& h) {
       data.insert(data.end(), (const char *)&h.data, ((const char *)&h.data)+crypto::HASH_SIZE);
       return *this;
     }

     OutVal& operator += (const std::string& v) {
       data.insert(data.end(), v.data(), v.data()+v.size());
       return *this;
     }

     template<typename T>
     OutVal& operator += (const T& v) {
       data.insert(data.end(), (const char *)&v, ((const char *)&v)+sizeof(T));
       return *this;
     }

     operator InVal () { return {data.data(), data.size()}; }
  };

  struct Batch;

  class DB
  {
    friend Batch;

    static std::map<std::string, std::weak_ptr<::leveldb::DB>>   g_db;
    static std::mutex                                            g_mx;

    std::unique_ptr<::leveldb::Iterator>    iterator_;

    void open();

    std::string                             path_;
    std::string                             pfx_;
    std::shared_ptr<::leveldb::DB>          db_;

  protected:
    ::leveldb::WriteBatch                   *batch_;

  public:
    DB(const std::string& name) : path_(name), batch_(nullptr) { open(); }
    DB(const std::string& name, const InVal& pfx) : path_(name), pfx_(pfx.data, pfx.data+pfx.size), batch_(nullptr) { open(); }
    DB(const DB& db) : path_(db.path_), pfx_(db.pfx_), db_(db.db_), batch_(nullptr)
    {
      THROW_WALLET_EXCEPTION_IF(!db_.get(),
        tools::error::wallet_internal_error, "database is not initialized");
    }
    DB(const DB& db, const InVal& pfx) : path_(db.path_), pfx_(db.pfx_), db_(db.db_), batch_(nullptr)
    {
      THROW_WALLET_EXCEPTION_IF(!db_.get(),
        tools::error::wallet_internal_error, "database is not initialized");
      pfx_.insert(pfx_.end(), pfx.data, pfx.data+pfx.size);
    }
    ~DB();

    DB range(const InVal& pfx) { return DB(*this, pfx); }

    bool get(const InVal& key, OutVal& val);
    void put(const InVal& key, const InVal& val);
    bool del(const InVal& key);

    bool first(OutVal& key, OutVal& val);
    bool last(OutVal& key, OutVal& val);
    bool skip(OutVal& key, OutVal& val, int n = 1);
    bool seek(const InVal& pfx, OutVal& key, OutVal& val);

    inline bool next(OutVal& key, OutVal& val) { return skip(key, val); }
    inline bool prev(OutVal& key, OutVal& val) { return skip(key, val, -1); }
  };

  struct Batch
  {
    std::shared_ptr<::leveldb::DB>  db_;
    ::leveldb::WriteBatch           batch_;

    template<typename... A>
    Batch(A& ... a) { attach(a...); }

    ~Batch();

    void attach() {}
    template<typename T, typename... A>
    void attach(T& db, A&... a) { attach(db); attach(a...); }
    void attach(DB& db);

    void write();

    std::vector<DB*> vdb_;
  };

}

#endif
