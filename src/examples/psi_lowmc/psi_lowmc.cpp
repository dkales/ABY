/**
 \file 		aes_test.cpp
 \author 	michael.zohner@ec-spride.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
			Copyright (C) 2015 Engineering Cryptographic Protocols Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
			it under the terms of the GNU Affero General Public License as published
			by the Free Software Foundation, either version 3 of the License, or
			(at your option) any later version.
			This program is distributed in the hope that it will be useful,
			but WITHOUT ANY WARRANTY; without even the implied warranty of
			MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
			GNU Affero General Public License for more details.
			You should have received a copy of the GNU Affero General Public License
			along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		AES Test class implementation.
 */

//Utility libs
#include "../../abycore/ENCRYPTO_utils/crypto/crypto.h"
#include "../../abycore/ENCRYPTO_utils/parse_options.h"
#include "../../abycore/ENCRYPTO_utils/socket.h"
//ABY Party class
#include "../../abycore/aby/abyparty.h"

#include "common/lowmccircuit.h"
#include "common/LowMC.h"

#include <sstream>
#include <iomanip>

//#define HASH_SIZE AES_BYTES
#define HASH_SIZE SHA256_OUT_BYTES


int32_t read_test_options(int32_t* argcp, char*** argvp, e_role* role, uint32_t* bitlen,
		uint32_t* secparam, string* address, uint16_t* port, e_sharing* sharing, bool* verbose, uint32_t* nthreads,
		bool* use_vec_ands) {

	uint32_t int_role = 0, int_port = 0, int_sharing = 0;
	bool useffc = false;

	parsing_ctx options[] = { { (void*) &int_role, T_NUM, "r", "Role: 0/1", true, false },
			{ (void*) bitlen, T_NUM, "b", "Bit-length, default 32", false, false },
			{ (void*) secparam, T_NUM, "s", "Symmetric Security Bits, default: 128", false, false },
			{ (void*) address, T_STR, "a", "IP-address, default: localhost", false, false },
			{ (void*) &int_port, T_NUM, "p", "Port, default: 7766", false, false },
			{ (void*) &int_sharing, T_NUM, "g", "Sharing in which the AES circuit should be evaluated [0: BOOL, 1: YAO, 4: SP_LUT], default: BOOL", false, false },
			{ (void*) verbose, T_FLAG, "v", "Do not print the result of the evaluation, default: off", false, false },
			{ (void*) nthreads, T_NUM, "t", "Number of threads, default: 1", false, false },
			{ (void*) use_vec_ands, T_FLAG, "u", "Use vector AND optimization for AES circuit for Bool sharing, default: off", false, false } };

	if (!parse_options(argcp, argvp, options, sizeof(options) / sizeof(parsing_ctx))) {
		print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
		cout << "Exiting" << endl;
		exit(0);
	}

	assert(int_role < 2);
	*role = (e_role) int_role;

	if (int_port != 0) {
		assert(int_port < 1 << (sizeof(uint16_t) * 8));
		*port = (uint16_t) int_port;
	}

	assert(int_sharing < S_LAST);
	assert(int_sharing != S_ARITH);
	*sharing = (e_sharing) int_sharing;

	//delete options;

	return 1;
}

int main(int argc, char** argv) {
	e_role role;
	uint32_t bitlen = 32, secparam = 128, nthreads = 1;
	uint16_t port = 7766;
	string address = "127.0.0.1";
	bool verbose = false;
	bool use_vec_ands = false;
	e_mt_gen_alg mt_alg = MT_OT;

	e_sharing sharing = S_BOOL;

	read_test_options(&argc, &argv, &role, &bitlen, &secparam, &address, &port, &sharing, &verbose, &nthreads, &use_vec_ands);

	seclvl seclvl = get_sec_lvl(secparam);

    if(role == SERVER) {
        constexpr size_t DB_SIZE = 1024 * 64;
        uint8_t enc_db[DB_SIZE*HASH_SIZE];
        uint8_t tmp[HASH_SIZE];
        //build db
        LowMC lowmc(0x1); //key is 1 for our testcase
        //extract the keys for the circuit
        {
            constexpr uint32_t exp_key_bytes = lowmcparam.blocksize /8 * (lowmcparam.nrounds+1);
            uint8_t buffer[exp_key_bytes];
            for (size_t i = 0; i < lowmcparam.nrounds + 1; i++) {
                bitsetToBytes<lowmcparam.blocksize/8>(lowmc.roundkeys[i], buffer + (i*lowmcparam.blocksize/8));
            }
            m_keybits.CreateBytes(exp_key_bytes);
            //use XORBytesReverse because we need the actual values in the circuit itself
            // we use its GetArr() method instead of GetBit(), therefore we must reverse the byte
            m_keybits.XORBytesReverse(buffer, 0, exp_key_bytes);
        }
        //extract lin and rc
        {
            constexpr uint32_t lin_layer_bytes = lowmcparam.blocksize * lowmcparam.blocksize / 8 * lowmcparam.nrounds;
            uint8_t buffer[lin_layer_bytes];
            for (size_t i = 0; i < lowmcparam.nrounds; i++) {
                for (size_t j = 0; j < lowmcparam.blocksize; j++) {
                    bitsetToBytes<lowmcparam.blocksize / 8>(lowmc.LinMatrices[i][lowmcparam.blocksize-1-j],
                                                     buffer + (i * lowmcparam.blocksize * lowmcparam.blocksize / 8) +
                                                     j * lowmcparam.blocksize / 8);
                }
            }
            m_linlayer.CreateBytes(lin_layer_bytes);
            m_linlayer.Copy(buffer, 0, lin_layer_bytes);//Dont XORBytesReverse cause we use getBit internally instead of the values itself
        }
        {
            constexpr uint32_t const_bytes = lowmcparam.blocksize / 8 * lowmcparam.nrounds;
            uint8_t buffer[const_bytes];
            for (size_t i = 0; i < lowmcparam.nrounds; i++) {
                bitsetToBytes<lowmcparam.blocksize / 8>(lowmc.roundconstants[i],
                                                 buffer + (i * lowmcparam.blocksize / 8));
            }
            m_roundconst.CreateBytes(const_bytes);
            m_roundconst.Copy(buffer, 0, const_bytes);//Dont XORBytesReverse cause we use getBit internally instead of the values itself
        }


        crypto crypt = crypto(seclvl.symbits, (uint8_t *) const_seed);
        for (size_t i = 1; i < DB_SIZE; i++) {
            crypt.hash(tmp, HASH_SIZE, (uint8_t *) (&i), sizeof(i));
            block a = bytesToBitset<HASH_SIZE>(tmp);
            //cout << i << ":" << hexStr(tmp, HASH_SIZE) << "\n";
            a = lowmc.encrypt(a);
            bitsetToBytes<HASH_SIZE>(a, enc_db + i*HASH_SIZE);
//            cout << i << ":" << hexStr(enc_db + i*HASH_SIZE, HASH_SIZE) << "\n";
        }
        cout << "Local encryption finished...\n";
        //send db to client
        CSocket ssock, sock;
        ssock.Socket();
        ssock.Bind(port+1);
        ssock.Listen(1);
        ssock.Accept(sock);
        sock.Send(&DB_SIZE, sizeof(size_t));
        sock.Send(enc_db, HASH_SIZE*DB_SIZE);

        size_t num_elements;
        sock.Receive(&num_elements, sizeof(size_t));
        sock.Close();
        ssock.Close();
        cout << "Send my database of "<< DB_SIZE << " elements, preparing to answer " << num_elements << " queries\n";

        execute_lowmc_circuit(role, (char*) address.c_str(), port, nullptr, nullptr, num_elements, nthreads, mt_alg, sharing, lowmcparam, 0, &crypt);
    }
    else {
        LowMC lowmc(0); //key is not relevant for matrices
        {
            constexpr uint32_t lin_layer_bytes = lowmcparam.blocksize * lowmcparam.blocksize / 8 * lowmcparam.nrounds;
            uint8_t buffer[lin_layer_bytes];
            for (size_t i = 0; i < lowmcparam.nrounds; i++) {
                for (size_t j = 0; j < lowmcparam.blocksize; j++) {
                    bitsetToBytes<lowmcparam.blocksize / 8>(lowmc.LinMatrices[i][lowmcparam.blocksize-1-j],
                                                     buffer + (i * lowmcparam.blocksize * lowmcparam.blocksize / 8) +
                                                     j * lowmcparam.blocksize / 8);
                }
            }
            m_linlayer.CreateBytes(lin_layer_bytes);
            m_linlayer.Copy(buffer, 0, lin_layer_bytes); //Dont XORBytesReverse cause we use getBit internally instead of the values itself
        }
        {
            constexpr uint32_t const_bytes = lowmcparam.blocksize / 8 * lowmcparam.nrounds;
            uint8_t buffer[const_bytes];
            for (size_t i = 0; i < lowmcparam.nrounds; i++) {
                bitsetToBytes<lowmcparam.blocksize / 8>(lowmc.roundconstants[i],
                                                 buffer + (i * lowmcparam.blocksize / 8));
            }
            m_roundconst.CreateBytes(const_bytes);
            m_roundconst.Copy(buffer, 0, const_bytes); //Dont XORBytesReverse cause we use getBit internally instead of the values itself
        }
        size_t dbsize;
        //recieve DB
        CSocket sock;
        sock.Socket();
        sock.Connect(address, port+1, 10000);
        sock.Receive(&dbsize, sizeof(size_t));
        uint8_t* enc_db = new uint8_t[dbsize*HASH_SIZE];
        sock.Receive(enc_db, dbsize*HASH_SIZE);

        //check for one or more elements to be in set
        size_t elements[] = {1,1234,88888,1000000,12345};
        size_t num_elements = sizeof(elements)/sizeof(elements[0]);
//        size_t num_elements = 256;
        uint8_t ele_hash[num_elements*HASH_SIZE];
        uint8_t* result;
        crypto crypt = crypto(seclvl.symbits, (uint8_t *) const_seed);
        for(size_t i = 0; i < num_elements; i++) {
            crypt.hash(ele_hash +i*HASH_SIZE, HASH_SIZE, (uint8_t *) (&elements[i]), sizeof(elements[i]));
//            crypt.hash(ele_hash +i*HASH_SIZE, HASH_SIZE, (uint8_t *) (&i), sizeof(i));
            //cout << i << ":" << hexStr(ele_hash + i*HASH_SIZE, HASH_SIZE) << "\n";
        }
        sock.Send(&num_elements, sizeof(num_elements));
        sock.Close();
        cout << "Recieved database of "<< dbsize << " elements, sending " << num_elements << " queries\n";

        execute_lowmc_circuit(role, (char*) address.c_str(), port, ele_hash, &result, num_elements, nthreads, mt_alg, sharing, lowmcparam, 0, &crypt);


        //compute set intersection
        for(size_t i = 0; i < num_elements; i++) {
            cout << i << ":" << hexStr(result + i*HASH_SIZE, HASH_SIZE) << "\n";
            for(size_t dbi = 0; dbi < dbsize; dbi++) {
                if(memcmp(result+i*HASH_SIZE, enc_db+dbi*HASH_SIZE, HASH_SIZE) == 0) {
                    cout << "Element " << elements[i] << " is in the servers set!\n";
                    break;
                }
            }
        }
        free(enc_db);
    }

	return 0;
}
