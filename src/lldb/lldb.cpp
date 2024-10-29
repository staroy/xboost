#include "lldb.h"

#include "leveldb/db.h"
#include "leveldb/cache.h"
#include "leveldb/options.h"

#include <iostream>
#include <sstream>

namespace lldb { 

  std::map<std::string, std::weak_ptr<::leveldb::DB >>  DB::g_db;
  std::mutex                                            DB::g_mx;

  DB::~DB()
  {
    if(!db_)
      return;

    std::lock_guard<std::mutex> lock(g_mx);
    auto it = g_db.find(path_.c_str());
    if (it != g_db.end())
    {
      if (it->second.use_count() < 2)
      {
        g_db.erase(path_.c_str());
        db_.reset();
      }
    }
  }

  void DB::open()
  {
    THROW_WALLET_EXCEPTION_IF(path_.empty(),
      tools::error::wallet_internal_error, "file path is empty");
    
    std::lock_guard<std::mutex> lock(g_mx);
    auto it = g_db.find(path_.c_str());
    if (it != g_db.end())
    {
      if (it->second.use_count() > 0)
      {
        db_ = it->second.lock();
        return;
      }
      else
        g_db.erase(path_.c_str());
    }
    
    ::leveldb::Options opt;
    //opt.paranoid_checks = true;
    opt.create_if_missing = true;
    opt.paranoid_checks = true;
    opt.block_cache = ::leveldb::NewLRUCache(8 * 1048576);  // 8MB cache
    
    ::leveldb::DB *pDB = 0;
    if( !::leveldb::DB::Open(opt, path_.c_str(), &pDB).ok() )
    {
      ::leveldb::Status rc = ::leveldb::RepairDB(path_.c_str(), opt);
      THROW_WALLET_EXCEPTION_IF(!rc.ok(),
        tools::error::wallet_internal_error, "Error repair levedb " + path_);
      rc = ::leveldb::DB::Open(opt, path_.c_str(), &pDB);
      THROW_WALLET_EXCEPTION_IF(!rc.ok(),
        tools::error::wallet_internal_error, "Error open levedb " + path_);
    }
    
    db_.reset(pDB);
    g_db[path_] = db_;
  }

  bool DB::get(const InVal& key, OutVal& val)
  {
    std::vector<char> buf(pfx_.begin(), pfx_.end());
    buf.insert(buf.end(), key.data, key.data + key.size);

    ::leveldb::Slice S(buf.data(), buf.size());

    ::leveldb::ReadOptions op;
    ::leveldb::Status rc = db_->Get(op, S, &val.data);

    return rc.ok();
  }

  void DB::put(const InVal& key, const InVal& val)
  {
    std::vector<char> buf(pfx_.begin(), pfx_.end());
    buf.insert(buf.end(), key.data, key.data + key.size);

    ::leveldb::Slice K(buf.data(), buf.size());
    ::leveldb::Slice V(val.data, val.size);

    if(!batch_)
    {
      ::leveldb::WriteOptions op;
      ::leveldb::Status rc = db_->Put(op, K, V);

      THROW_WALLET_EXCEPTION_IF(!rc.ok(),
        tools::error::wallet_internal_error, "database error Put");
    }
    else
      batch_->Put(K, V);
  }

  bool DB::del(const InVal& key)
  {
    std::vector<char> buf(pfx_.begin(), pfx_.end());
    buf.insert(buf.end(), key.data, key.data + key.size);

    ::leveldb::Slice K(buf.data(), buf.size());

    if(!batch_)
    {
      ::leveldb::WriteOptions op;
      ::leveldb::Status rc = db_->Delete(op, K);

      if(!rc.ok())
        return false;
    }
    else
      batch_->Delete(K);

    return true;
  }

  bool DB::first(OutVal& key, OutVal& val)
  {
    THROW_WALLET_EXCEPTION_IF(!db_.get(),
      tools::error::wallet_internal_error, "database not initialized");

    iterator_.reset();
    
    ::leveldb::ReadOptions op;
    iterator_.reset( db_->NewIterator(op) );

    if(pfx_.size() > 0)
    {
      ::leveldb::Slice slice(pfx_.data(), pfx_.size());
      iterator_->Seek(slice);
    }
    else
      iterator_->SeekToFirst();

    if(iterator_->Valid())
    {
      ::leveldb::Slice k = iterator_->key();
      if(k.size() >= pfx_.size() && memcmp(k.data(), pfx_.data(), pfx_.size()) == 0)
      {
        ::leveldb::Slice s = iterator_->value();
        val.data.assign(s.data(), s.data()+s.size());
        key.data.assign(k.data()+pfx_.size(), k.data()+k.size());
        return true;
      }
    }

    iterator_.reset();
    return false;
  }

  bool DB::last(OutVal& key, OutVal& val)
  {
    THROW_WALLET_EXCEPTION_IF(!db_.get(),
      tools::error::wallet_internal_error, "database not initialized");
    
    iterator_.reset();
    
    ::leveldb::ReadOptions op;
    iterator_.reset( db_->NewIterator(op) );

    if(pfx_.size() > 0)
    {
      std::vector<char> b(pfx_.begin(), pfx_.end());
      for(auto n=b.rbegin();n<b.rend();n++){
        uint16_t c=*n; c++; *n=c;
        if(c<256) break;
      }
      ::leveldb::Slice slice(b.data(), b.size());
      iterator_->Seek(slice);
      if(iterator_->Valid())
        iterator_->Prev();
      else
        iterator_->SeekToLast();
    }
    else
      iterator_->SeekToLast();

    if(iterator_->Valid())
    {
      ::leveldb::Slice k = iterator_->key();
      if(k.size() >= pfx_.size() && memcmp(k.data(), pfx_.data(), pfx_.size()) == 0)
      {
        ::leveldb::Slice s = iterator_->value();
        val.data.assign(s.data(), s.data()+s.size());
        key.data.assign(k.data()+pfx_.size(), k.data()+k.size());
        return true;
      }
    }

    iterator_.reset();
    return false;
  }

  bool DB::skip(OutVal& key, OutVal& val, int n)
  {
    THROW_WALLET_EXCEPTION_IF(!db_.get(),
      tools::error::wallet_internal_error, "database not initialized");
    
    THROW_WALLET_EXCEPTION_IF(!iterator_,
      tools::error::wallet_internal_error, "iterator not initialized");

    if(n>0)
    {
      for(; n>0 && iterator_->Valid(); n--)
        iterator_->Next();
    }
    else if(n<0)
    {
      for(; n<0 && iterator_->Valid(); n++)
        iterator_->Prev();
    }

    if(iterator_->Valid())
    {
      ::leveldb::Slice k = iterator_->key();
      if(k.size() >= pfx_.size() && memcmp(k.data(), pfx_.data(), pfx_.size()) == 0)
      {
        ::leveldb::Slice s = iterator_->value();
        val.data.assign(s.data(), s.data()+s.size());
        key.data.assign(k.data()+pfx_.size(), k.data()+k.size());
        return true;
      }
    }

    iterator_.reset();
    return false;
  }

  bool DB::seek(const InVal& pfx, OutVal& key, OutVal& val)
  {
    THROW_WALLET_EXCEPTION_IF(!db_.get(),
      tools::error::wallet_internal_error, "database not initialized");
    
    iterator_.reset();
    
    ::leveldb::ReadOptions op;
    iterator_.reset( db_->NewIterator(op) );

    std::vector<char> S(pfx_.data(), pfx_.data() + pfx_.size());
    S.insert(S.end(), pfx.data, pfx.data + pfx.size);

    ::leveldb::Slice slice(S.data(), S.size());
    iterator_->Seek(slice);

    if(iterator_->Valid())
    {
      ::leveldb::Slice k = iterator_->key();
      if(k.size() >= pfx_.size() && memcmp(k.data(), pfx_.data(), pfx_.size()) == 0)
      {
        ::leveldb::Slice s = iterator_->value();
        val.data.assign(s.data(), s.data()+s.size());
        key.data.assign(k.data()+pfx_.size(), k.data()+k.size());
        return true;
      }
    }
    return false;
  }

  void Batch::attach(DB& db)
  {
    THROW_WALLET_EXCEPTION_IF(!db.db_.get(),
      tools::error::wallet_internal_error, "db is null");
    if(db_.get()) {
      THROW_WALLET_EXCEPTION_IF(db_.get() != db.db_.get(),
        tools::error::wallet_internal_error, "db is other ");
    }
    else
      db_ = db.db_;
    db.batch_ = &batch_;
    vdb_.push_back(&db);
  }

  Batch::~Batch()
  {
    for(auto a : vdb_)
      a->batch_ = nullptr;
  }

  void Batch::write()
  {
    if(db_)
    {
      ::leveldb::WriteOptions op;
      ::leveldb::Status rc = db_->Write(op, &batch_);

      if(!rc.ok())
        std::cout << "error commit\n";
      THROW_WALLET_EXCEPTION_IF(!rc.ok(),
        tools::error::wallet_internal_error, "error batch commit");
    }
  }

}
