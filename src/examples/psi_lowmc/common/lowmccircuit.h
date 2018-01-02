/**
 \file 		aescircuit.h
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
 \brief		Implementation of AESCiruit
 */

#ifndef __LOWMCCIRC_H_
#define __LOWMCCIRC_H_

#include "../../../abycore/circuit/circuit.h"
#include "../../../abycore/aby/abyparty.h"
#include "../../../abycore/ENCRYPTO_utils/cbitvector.h"
#include "../../../abycore/ENCRYPTO_utils/typedefs.h"
#include "../../../abycore/ENCRYPTO_utils/graycode.h"

#include <cassert>


inline std::string hexStr(BYTE *data, int len)
{
    std::stringstream ss;
    ss<<std::hex<<std::setfill('0');
    for(int i(0);i<len;++i)
        ss<<std::setw(2)<<(int)data[i];
    return ss.str();
}


static const BYTE mpccseed[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

/* versions of the lowmc cipher: short term security, short term wide, long term security, long term wide */
enum LowMCVersion {
    STLowMC = 0, LTLowMC = 1
};

struct LowMCParams {
    uint32_t nsboxes;
    uint32_t keysize;
    uint32_t blocksize;
    uint32_t data;
    uint32_t nrounds;
};

struct matmul {
    UGATE_T** matrix;
    uint32_t column;
};

//parameters: sboxes (m), key-length (k), statesize (n), data (d), rounds (r)
static constexpr LowMCParams stp = { 49, 80, 256, 64, 12 };
static constexpr LowMCParams ltp = { 63, 128, 256, 128, 14 };
static constexpr LowMCParams lowmcparam = ltp; //{ 10, 128, 128, 128, 32 };

static const LowMCParams lowmcparamlookup[] = { stp, ltp};

static uint32_t m_constCtr;
static uint32_t m_linCtr;
extern CBitVector m_keybits;
extern CBitVector m_roundconst;
extern CBitVector m_linlayer;
static code* m_tGrayCode;
static uint32_t m_nZeroGate;


int32_t execute_lowmc_circuit(e_role role, char* address, uint16_t port, uint8_t* inval, uint8_t** outval, uint32_t nvals, uint32_t nthreads,
                              e_mt_gen_alg mt_alg, e_sharing sharing, const LowMCParams& param, uint32_t maxgates, crypto* crypt);

share* BuildLowMCCircuit(share* val, share* key, BooleanCircuit* circ, const LowMCParams& param, uint32_t zerogate, crypto* crypt);
void LowMCAddRoundKey(vector<uint32_t>& val, vector<uint32_t> key, uint32_t locmcstatesize, uint32_t round, BooleanCircuit* circ);
void LowMCMultiplyState(vector<uint32_t>& state, uint32_t lowmcstatesize, BooleanCircuit* circ);
void LowMCXORConstants(vector<uint32_t>& state, uint32_t lowmcstatesize, BooleanCircuit* circ);
void LowMCXORMultipliedKey(vector<uint32_t>& state, vector<uint32_t> key, uint32_t lowmcstatesize, uint32_t round, BooleanCircuit* circ);
void LowMCPutSBoxLayer(vector<uint32_t>& input, uint32_t numsboxes, uint32_t statesize, BooleanCircuit* circ);
void LowMCPutSBox(uint32_t& o1, uint32_t& o2, uint32_t& o3, BooleanCircuit* circ);

void LowMCMultiplyStateCallback(vector<uint32_t>& state, uint32_t lowmcstatesize, BooleanCircuit* circ);
void CallbackMultiplication(GATE* gate, void* matmulinfos);
void CallbackBuild4RMatrixAndMultiply(GATE* gate, void* matrix);
void CallbackMultiplyAndDestroy4RMatrix(GATE* gate, void* matrix);


void FourRussiansMatrixMult(vector<uint32_t>& state, uint32_t lowmcstatesize, BooleanCircuit* circ);

#endif /* __LOWMCCIRC_H_ */
