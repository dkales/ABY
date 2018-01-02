#ifndef __LowMC_h__
#define __LowMC_h__

#include <bitset>
#include <vector>
#include <string>
#include <climits>
#include <iterator>


//static const LowMCParams ltp = { 63, 128, 256, 128, 14 };
const unsigned numofboxes = 63;    // Number of Sboxes
const unsigned blocksize = 256;   // Block size in bits
const unsigned keysize = 128; // Key size in bits
const unsigned rounds = 14; // Number of rounds

const unsigned identitysize = blocksize - 3*numofboxes;
                  // Size of the identity part in the Sbox layer

typedef std::bitset<blocksize> block; // Store messages and states
typedef std::bitset<keysize> keyblock;


static unsigned char lookup[16] = {
        0x0, 0x8, 0x4, 0xc, 0x2, 0xa, 0x6, 0xe,
        0x1, 0x9, 0x5, 0xd, 0x3, 0xb, 0x7, 0xf, };

inline uint8_t reverse(uint8_t n) {
    // Reverse the top and bottom nibble then swap them.
    return (lookup[n&0b1111] << 4) | lookup[n>>4];
}

template<int numBytes>
std::bitset<numBytes * CHAR_BIT> bytesToBitset(uint8_t *data)
{
    std::bitset<numBytes * CHAR_BIT> b = 0;

    for(int i = 0; i < numBytes; i++)
    {
        b <<= CHAR_BIT;
        b |= data[i];
    }

    return b;
}

template<int numBytes>
void bitsetToBytes(std::bitset<numBytes * CHAR_BIT>& data, uint8_t* out)
{
    std::bitset<numBytes * CHAR_BIT> b = data;
    std::bitset<numBytes * CHAR_BIT> a(0xFF);

    for(int i = numBytes -1; i >= 0; i--)
    {
        out[i] = (b & a).to_ulong();
        b >>= CHAR_BIT;
    }
}

template <class RanIt, class OutIt>
void make_hex(RanIt b, RanIt e, OutIt o) {
    static const char rets[] = "0123456789ABCDEF";

    if ((e-b) %4 != 0)
        throw std::runtime_error("Length must be a multiple of 4");

    while (b != e) {
        int index =
            ((*(b + 0) - '0') << 3) |
            ((*(b + 1) - '0') << 2) |
            ((*(b + 2) - '0') << 1) |
            ((*(b + 3) - '0') << 0);
        *o++ = rets[index];
        b += 4;
    }
}

inline void printhexblock(const std::string&info, block b) {
    std::string bin = b.to_string();
    std::cout << info << ": ";
    make_hex(bin.begin(), bin.end(), std::ostream_iterator<char>(std::cout));
    std::cout << std::endl;
}

class LowMC {
public:
    LowMC (keyblock k = 0) {
        key = k;
        instantiate_LowMC();
        keyschedule();   
    };

    block encrypt (const block message);
    block decrypt (const block message);
    void lowmc_set_key (keyblock k);

    void print_matrices();

    //for extraction on the server side
    std::vector<std::vector<block>> LinMatrices;
    std::vector<block> roundconstants;
    std::vector<block> roundkeys;

private:
// LowMC private data members //
    // The Sbox and its inverse    
    const std::vector<unsigned> Sbox =
        {0x00, 0x01, 0x03, 0x06, 0x07, 0x04, 0x05, 0x02};
    const std::vector<unsigned> invSbox =
        {0x00, 0x01, 0x07, 0x02, 0x05, 0x06, 0x03, 0x04};
        // Stores the binary matrices for each round
    std::vector<std::vector<block>> invLinMatrices;
        // Stores the inverses of LinMatrices
        // Stores the round constants
    keyblock key = 0;
        //Stores the master key
    std::vector<std::vector<keyblock>> KeyMatrices;
        // Stores the matrices that generate the round keys
        // Stores the round keys
    
// LowMC private functions //
    block Substitution (const block message);
        // The substitution layer
    block invSubstitution (const block message);
        // The inverse substitution layer

    block MultiplyWithGF2Matrix
        (const std::vector<block> matrix, const block message);    
        // For the linear layer
    block MultiplyWithGF2Matrix_Key
        (const std::vector<keyblock> matrix, const keyblock k);
        // For generating the round keys

    void keyschedule ();
        //Creates the round keys from the master key

    void instantiate_LowMC ();
        //Fills the matrices and roundconstants with pseudorandom bits 
   
// Binary matrix functions //   
    unsigned rank_of_Matrix (const std::vector<block> matrix);
    unsigned rank_of_Matrix_Key (const std::vector<keyblock> matrix);
    std::vector<block> invert_Matrix (const std::vector<block> matrix);

// Random bits functions //
    block getrandblock ();
    keyblock getrandkeyblock ();
    bool  getrandbit ();

};

#endif
