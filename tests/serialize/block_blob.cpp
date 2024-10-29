#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "string_tools.h"

int main(int argc, char const *argv[])
{
    std::string ik;
    std::cin >> ik;

    cryptonote::block b, b2;
    cryptonote::txin_gen in;
    in.proofs.resize(1);
    in.proofs[0].v.resize(2);
    b.miner_tx.vin.push_back(in);
    b.miner_tx.vout.resize(1);
    b.tx_hashes.resize(1);

    std::string data;
    bool r = cryptonote::block_to_blob(b, data);
    std::cout << "block_to_blob result: " << r << ", data size: " << data.size() << std::endl;
    std::cout << "data hex: " << epee::string_tools::buff_to_hex_nodelimer(data) << std::endl;
    binary_archive<false> iar{epee::strspan<std::uint8_t>(data)};
    r = ::serialization::serialize(iar, b2);
    std::cout << "parse result: " << r << std::endl;
}
