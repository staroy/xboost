
#include <boost/optional/optional.hpp>
#include <boost/range/adaptor/indexed.hpp>
#include <gtest/gtest.h>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <vector>

#include "byte_stream.h"
#include "crypto/hash.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "serialization/json_object.h"
#include "rpc/daemon_messages.h"


namespace test
{
    cryptonote::transaction
    make_miner_transaction(cryptonote::account_public_address const& to, crypto::secret_key const& sec)
    {
        cryptonote::keypair key = cryptonote::keypair::generate(hw::get_device("default"));
        crypto::secret_key mine_key = key.sec;
        
        crypto::hash hash;
        crypto::cn_fast_hash(key.pub.data, sizeof(crypto::public_key), hash);
        
        crypto::signature mine_sig;
        crypto::generate_signature(hash, to.m_spend_public_key, sec, mine_sig);
        
        std::vector<cryptonote::data_tx_proof> proofs;

        cryptonote::transaction tx{};
        if (!cryptonote::construct_miner_tx(0, 0, 5000, 500, 500, to, proofs, mine_key, mine_sig, tx))
            throw std::runtime_error{"transaction construction error"};

        crypto::hash id{0};
        if (!cryptonote::get_transaction_hash(tx, id))
            throw std::runtime_error{"could not get transaction hash"};

        return tx;
    }

    cryptonote::transaction
    make_transaction(
        cryptonote::account_keys const& from,
        std::vector<cryptonote::transaction> const& sources,
        std::vector<cryptonote::account_public_address> const& destinations,
        bool rct,
        bool bulletproof)
    {
        std::uint64_t source_amount = 0;
        std::vector<cryptonote::tx_source_entry> actual_sources;
        for (auto const& source : sources)
        {
            std::vector<cryptonote::tx_extra_field> extra_fields;
            if (!cryptonote::parse_tx_extra(source.extra, extra_fields))
                throw std::runtime_error{"invalid transaction"};

            cryptonote::tx_extra_pub_key key_field{};
            if (!cryptonote::find_tx_extra_field_by_type(extra_fields, key_field))
                throw std::runtime_error{"invalid transaction"};

            for (auto const input : boost::adaptors::index(source.vout))
            {
                source_amount += input.value().amount;
                auto const& key = boost::get<cryptonote::txout_to_key>(input.value().target);

                actual_sources.push_back(
                    {{}, 0, key_field.pub_key, {}, std::size_t(input.index()), input.value().amount, rct, rct::identity()}
                );

                for (unsigned ring = 0; ring < 10; ++ring)
                    actual_sources.back().push_output(input.index(), key.key, input.value().amount);
            }
        }

        std::vector<cryptonote::tx_destination_entry> to;
        for (auto const& destination : destinations)
            to.push_back({(source_amount / destinations.size()), destination, false});

        cryptonote::transaction tx{};

        crypto::secret_key tx_key{};
        std::vector<crypto::secret_key> extra_keys{};

        std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses;
        subaddresses[from.m_account_address.m_spend_public_key] = {0,0};

        if (!cryptonote::construct_tx_and_get_tx_key(from, subaddresses, actual_sources, to, boost::none, {}, tx, 0, tx_key, extra_keys, rct, { bulletproof ? rct::RangeProofBulletproof : rct::RangeProofBorromean, bulletproof ? 2 : 0 }))
            throw std::runtime_error{"transaction construction error"};

        return tx;
    }
}

namespace
{
    template<typename T>
    T test_json(const T& value)
    {
      epee::byte_stream buffer;
      {
        rapidjson::Writer<epee::byte_stream> dest{buffer};
        cryptonote::json::toJsonValue(dest, value);
      }

      rapidjson::Document doc;
      doc.Parse(reinterpret_cast<const char*>(buffer.data()), buffer.size());
      if (doc.HasParseError())
      {
        throw cryptonote::json::PARSE_FAIL();
      }

      T out{};
      cryptonote::json::fromJsonValue(doc, out);
      return out;
    }
} // anonymous

TEST(JsonSerialization, VectorBytes)
{
    EXPECT_EQ(std::vector<std::uint8_t>{}, test_json(std::vector<std::uint8_t>{}));
    EXPECT_EQ(std::vector<std::uint8_t>{0x00}, test_json(std::vector<std::uint8_t>{0x00}));
}

TEST(JsonSerialization, InvalidVectorBytes)
{
    rapidjson::Document doc;
    doc.SetString("1");

    std::vector<std::uint8_t> out;
    EXPECT_THROW(cryptonote::json::fromJsonValue(doc, out), cryptonote::json::BAD_INPUT);
}

TEST(JsonSerialization, MinerTransaction)
{
    cryptonote::account_base acct;
    acct.generate();
    const auto miner_tx = test::make_miner_transaction(acct.get_keys().m_account_address, acct.get_keys().m_spend_secret_key);

    crypto::hash tx_hash{};
    ASSERT_TRUE(cryptonote::get_transaction_hash(miner_tx, tx_hash));

    cryptonote::transaction miner_tx_copy = test_json(miner_tx);

    crypto::hash tx_copy_hash{};
    ASSERT_TRUE(cryptonote::get_transaction_hash(miner_tx_copy, tx_copy_hash));
    EXPECT_EQ(tx_hash, tx_copy_hash);

    cryptonote::blobdata tx_bytes{};
    cryptonote::blobdata tx_copy_bytes{};

    ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(miner_tx, tx_bytes));
    ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(miner_tx_copy, tx_copy_bytes));

    EXPECT_EQ(tx_bytes, tx_copy_bytes);
}

TEST(JsonSerialization, RegularTransaction)
{
    cryptonote::account_base acct1;
    acct1.generate();

    cryptonote::account_base acct2;
    acct2.generate();

    const auto miner_tx = test::make_miner_transaction(acct1.get_keys().m_account_address, acct1.get_keys().m_spend_secret_key);
    const auto tx = test::make_transaction(
        acct1.get_keys(), {miner_tx}, {acct2.get_keys().m_account_address}, false, false
    );

    crypto::hash tx_hash{};
    ASSERT_TRUE(cryptonote::get_transaction_hash(tx, tx_hash));

    cryptonote::transaction tx_copy = test_json(tx);

    crypto::hash tx_copy_hash{};
    ASSERT_TRUE(cryptonote::get_transaction_hash(tx_copy, tx_copy_hash));
    EXPECT_EQ(tx_hash, tx_copy_hash);

    cryptonote::blobdata tx_bytes{};
    cryptonote::blobdata tx_copy_bytes{};

    ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(tx, tx_bytes));
    ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(tx_copy, tx_copy_bytes));

    EXPECT_EQ(tx_bytes, tx_copy_bytes);
}

TEST(JsonSerialization, RingctTransaction)
{
    cryptonote::account_base acct1;
    acct1.generate();

    cryptonote::account_base acct2;
    acct2.generate();

    const auto miner_tx = test::make_miner_transaction(acct1.get_keys().m_account_address, acct1.get_keys().m_spend_secret_key);
    const auto tx = test::make_transaction(
        acct1.get_keys(), {miner_tx}, {acct2.get_keys().m_account_address}, true, false
    );

    crypto::hash tx_hash{};
    ASSERT_TRUE(cryptonote::get_transaction_hash(tx, tx_hash));

    cryptonote::transaction tx_copy = test_json(tx);

    crypto::hash tx_copy_hash{};
    ASSERT_TRUE(cryptonote::get_transaction_hash(tx_copy, tx_copy_hash));
    EXPECT_EQ(tx_hash, tx_copy_hash);

    cryptonote::blobdata tx_bytes{};
    cryptonote::blobdata tx_copy_bytes{};

    ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(tx, tx_bytes));
    ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(tx_copy, tx_copy_bytes));

    EXPECT_EQ(tx_bytes, tx_copy_bytes);
}

TEST(JsonSerialization, BulletproofTransaction)
{
    cryptonote::account_base acct1;
    acct1.generate();

    cryptonote::account_base acct2;
    acct2.generate();

    const auto miner_tx = test::make_miner_transaction(acct1.get_keys().m_account_address, acct1.get_keys().m_spend_secret_key);
    const auto tx = test::make_transaction(
        acct1.get_keys(), {miner_tx}, {acct2.get_keys().m_account_address}, true, true
    );

    crypto::hash tx_hash{};
    ASSERT_TRUE(cryptonote::get_transaction_hash(tx, tx_hash));

    cryptonote::transaction tx_copy = test_json(tx);

    crypto::hash tx_copy_hash{};
    ASSERT_TRUE(cryptonote::get_transaction_hash(tx_copy, tx_copy_hash));
    EXPECT_EQ(tx_hash, tx_copy_hash);

    cryptonote::blobdata tx_bytes{};
    cryptonote::blobdata tx_copy_bytes{};

    ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(tx, tx_bytes));
    ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(tx_copy, tx_copy_bytes));

    EXPECT_EQ(tx_bytes, tx_copy_bytes);
}

TEST(JsonRpcSerialization, HandlerFromJson)
{
  cryptonote::rpc::FullMessage req_full("{\"jsonrpc\":\"2.0\",\"method\":\"get_hashes_fast\",\"params\":[1]}", true);
  cryptonote::rpc::GetHashesFast::Request request{};
  EXPECT_THROW(request.fromJson(req_full.getMessage()), cryptonote::json::WRONG_TYPE);
}
