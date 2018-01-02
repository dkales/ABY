/**
 \file 		lowmccircuit.cpp
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
#include "lowmccircuit.h"


CBitVector m_keybits;
CBitVector m_roundconst;
CBitVector m_linlayer;


int32_t execute_lowmc_circuit(e_role role, char* address, uint16_t port, uint8_t* inval, uint8_t** outval, uint32_t nvals, uint32_t nthreads,
                           e_mt_gen_alg mt_alg, e_sharing sharing, const LowMCParams& param, uint32_t maxgates, crypto* crypt) {

    uint32_t bitlen = 32, ctr = 0, exp_key_bitlen = param.blocksize * (param.nrounds+1), zero_gate, lowmc_data_bytes = param.blocksize/8;

    ABYParty* party;
    if(maxgates > 0)
        party = new ABYParty(role, address, port, crypt->get_seclvl(), bitlen, nthreads, mt_alg, maxgates);
    else
        party = new ABYParty(role, address, port, crypt->get_seclvl(), bitlen, nthreads, mt_alg);

    vector<Sharing*>& sharings = party->GetSharings();

    CBitVector input, key;

    input.CreateBytes(lowmc_data_bytes * nvals);
    if(role == CLIENT) {
        input.XORBytesReverse(inval, 0, nvals*lowmc_data_bytes);
    }

    //Use a dummy key for benchmark reasons
    key.CreateBytes(exp_key_bitlen/8);
    if(role == SERVER) {
        key.Copy(m_keybits);
    }


    Circuit* circ = sharings[sharing]->GetCircuitBuildRoutine();
    //Circuit build routine works for Boolean circuits only
    assert(circ->GetCircuitType() == C_BOOLEAN);

    share *s_in, *s_key, *s_ciphertext;
    s_in = circ->PutSIMDINGate(nvals, input.GetArr(), param.blocksize, CLIENT);
    s_key = circ->PutINGate(key.GetArr(), exp_key_bitlen, SERVER);
    s_key = circ->PutRepeaterGate(nvals, s_key);
    zero_gate = circ->PutConstantGate(0, nvals);

    s_ciphertext = BuildLowMCCircuit(s_in, s_key, (BooleanCircuit*) circ, param, zero_gate, crypt);

    s_ciphertext = circ->PutOUTGate(s_ciphertext, CLIENT);

    party->ExecCircuit();

    if(role == CLIENT) {
        //fix endianess
        *outval = s_ciphertext->get_clear_value_ptr();
        input.CreateZeros(nvals*param.blocksize);
        input.XORBytesReverse(*outval,0,nvals*param.blocksize/8);
        memcpy(*outval, input.GetArr(), nvals*param.blocksize/8);
    }

    cout << party->GetTiming(P_SETUP) << "\t" << party->GetTiming(P_ONLINE) << "\t" << party->GetTiming(P_TOTAL) << endl;

    return 1;
}

share* BuildLowMCCircuit(share* val, share* key, BooleanCircuit* circ, const LowMCParams& param, uint32_t zerogate, crypto* crypt) {
    uint32_t round, byte, i, j, k;
    uint32_t nsboxes = param.nsboxes;
    uint32_t statesize = param.blocksize;
    uint32_t nrounds = param.nrounds;

    vector<uint32_t> state(statesize);
    m_nZeroGate = zerogate;
    m_linCtr = 0;
    m_constCtr = 0;

    //Build the GrayCode for the optimal window-size
    uint32_t wsize = floor_log2(statesize);
    m_tGrayCode = build_code(wsize);

    //copy the input to the current state
    for (i = 0; i < statesize; i++)
        state[i] = val->get_wire_id(i);

//    circ->PutPrintValueGate(new boolshare(state, circ), "input");
//    vector<uint32_t> key_wires(key->get_wires());
//    circ->PutPrintValueGate(new boolshare(std::vector<uint32_t>(key_wires.begin(), key_wires.begin() + statesize), circ), "key");
    LowMCXORMultipliedKey(state, key->get_wires(), statesize, 0, circ); //ARK
    for (round = 1; round <= nrounds; round++) {

        //substitution via 3-bit SBoxes
        LowMCPutSBoxLayer(state, nsboxes, statesize, circ);
//        if(round == round)
//            circ->PutPrintValueGate(new boolshare(state, circ), "sbox");


        //multiply state with GF2Matrix
//        LowMCMultiplyState(state, statesize, circ);//Naive version of the state multiplication
        FourRussiansMatrixMult(state, statesize, circ);//4 Russians version of the state multiplication
        //LowMCMultiplyStateCallback(state, statesize, circ); //use callbacks to perform the multiplication in plaintext
//        if(round == round) {
//            circ->PutPrintValueGate(new boolshare(state, circ), "lin");
//        }

        //XOR constants
        LowMCXORConstants(state, statesize, circ);
//        if(round == 1) {
//            circ->PutPrintValueGate(new boolshare(state, circ), "rc");
//        }

        //XOR with multiplied key
        LowMCXORMultipliedKey(state, key->get_wires(), statesize, round, circ);
//        if(round == 1) {
//            circ->PutPrintValueGate(new boolshare(state, circ), "rk");
//        }

    }

    destroy_code(m_tGrayCode);

#ifdef PRINT_PERFORMANCE_STATS
    cout << "Total Number of Boolean Gates: " << circ->GetNumGates() << endl;
#endif

    return new boolshare(state, circ);
}

void LowMCAddRoundKey(vector<uint32_t>& val, vector<uint32_t> key, uint32_t lowmcstatesize, uint32_t round, BooleanCircuit* circ) {
    for (uint32_t i = 0; i < lowmcstatesize; i++) {
        val[i] = circ->PutXORGate(val[i], key[i+(1+round) * lowmcstatesize]);
    }
}

//Multiply the state using a linear matrix
void LowMCMultiplyState(vector<uint32_t>& state, uint32_t lowmcstatesize, BooleanCircuit* circ) {
    vector<uint32_t> tmpstate(lowmcstatesize);
    for (uint32_t i = 0; i < lowmcstatesize; i++) {
        tmpstate[i] = m_nZeroGate;
        for (uint32_t j = 0; j < lowmcstatesize; j++) {
            if (m_linlayer.GetBit(m_linCtr + j + i*lowmcstatesize)) {
                tmpstate[i] = circ->PutXORGate(tmpstate[i], state[j]);
            }
        }
    }
    m_linCtr += lowmcstatesize*lowmcstatesize;
    state = tmpstate;
}

//XOR constants on the state
void LowMCXORConstants(vector<uint32_t>& state, uint32_t lowmcstatesize, BooleanCircuit* circ) {
    for (uint32_t i = 0; i < lowmcstatesize; i++, m_constCtr++) {
        if (m_roundconst.GetBit(m_constCtr)) {
            state[i] = circ->PutINVGate(state[i]);
        }
    }

}

//Multiply the key with a 192x192 matrix and XOR the result on the state.
void LowMCXORMultipliedKey(vector<uint32_t>& state, vector<uint32_t> key, uint32_t lowmcstatesize, uint32_t round, BooleanCircuit* circ) {
    uint32_t tmp;
    /*for(uint32_t i = 0; i < MPCC_STATE_SIZE; i++) {
     tmp = 0;
     for(uint32_t j = 0; j < MPCC_STATE_SIZE; j++, m_nRndCtr++) {
     if(m_vRandomBits.GetBit(m_nRndCtr)) {
     tmp = PutXORGate(tmp, key[j]);
     }
     }
     state[i] = PutXORGate(state[i], tmp);
     }*/
    //Assume outsourced key-schedule
    for (uint32_t i = 0; i < lowmcstatesize; i++) {
        state[i] = circ->PutXORGate(state[i], key[i+(round) * lowmcstatesize]);

    }

}

//Put a layer of 3-bit LowMC SBoxes
void LowMCPutSBoxLayer(vector<uint32_t>& input, uint32_t nsboxes, uint32_t statesize, BooleanCircuit* circ) {
    for (uint32_t i = 0; i < nsboxes * 3; i += 3) {
        LowMCPutSBox(input[statesize-1-(i+2)], input[statesize-1-(i+1)], input[statesize-1-(i+0)], circ);
    }
}

//Put a 3-bit LowMC SBoxes
void LowMCPutSBox(uint32_t& o1, uint32_t& o2, uint32_t& o3, BooleanCircuit* circ) {
    uint32_t i1 = o1;
    uint32_t i2 = o2;
    uint32_t i3 = o3;

    uint32_t ni1 = circ->PutINVGate(i1);
    uint32_t ni2 = circ->PutINVGate(i2);
    uint32_t ni3 = circ->PutINVGate(i3);

    //C = B * C + A
    o1 = circ->PutXORGate(circ->PutANDGate(i2, i3), i1);

    //E = A * (NOT C) + B
    o2 = circ->PutXORGate(circ->PutANDGate(i1, ni3), i2);

    //F = (NOT ((NOT B) * (NOT A))) + C
    o3 = circ->PutXORGate(circ->PutINVGate(circ->PutANDGate(ni2, ni1)), i3);
}
//void LowMCPutSBox(uint32_t& o1, uint32_t& o2, uint32_t& o3, BooleanCircuit* circ) {
//    uint32_t i1 = o1;
//    uint32_t i2 = o2;
//    uint32_t i3 = o3;
//
//    uint32_t i12 = circ->PutXORGate(i1, i2);
//    uint32_t i123 = circ->PutXORGate(i12, i3);
//
//    //C = A + B*C
//    o1 = circ->PutXORGate(circ->PutANDGate(i2, i3), i1);
//
//    //E = A + B + A*C
//    o2 = circ->PutXORGate(circ->PutANDGate(i1, i3), i12);
//
//    //F = A + B + C + A*B
//    o3 = circ->PutXORGate(circ->PutANDGate(i2, i1), i123);
//}

void FourRussiansMatrixMult(vector<uint32_t>& state, uint32_t lowmcstatesize, BooleanCircuit* circ) {
    //round to nearest square for optimal window size
    uint32_t wsize = floor_log2(lowmcstatesize);

    //will only work if the statesize is a multiple of the window size
    uint32_t* lutptr;
    uint32_t* lut = (uint32_t*) malloc(sizeof(uint32_t) * (1 << wsize));
    uint32_t i, j, tmp = 0;

    lut[0] = m_nZeroGate;	//circ->PutConstantGate(0, 1);

    vector<uint32_t> tmpstate(ceil_divide(lowmcstatesize, wsize) * wsize, lut[0]);
    //pad the state to a multiple of the window size and fill with zeros
    vector<uint32_t> state_pad(ceil_divide(lowmcstatesize, wsize) * wsize, lut[0]);
    for (i = 0; i < lowmcstatesize; i++)
        state_pad[i] = state[i];

    for (i = 0; i < ceil_divide(lowmcstatesize, wsize); i++) { //for each column-window
        for (j = 1; j < (1 << wsize); j++) {
            lut[m_tGrayCode->ord[j]] = circ->PutXORGate(lut[m_tGrayCode->ord[j - 1]], state_pad[i * wsize + m_tGrayCode->inc[j - 1]]);
        }

        for (j = 0; j < lowmcstatesize; j++) {
            m_linlayer.GetBits((BYTE*) &tmp, m_linCtr+i*wsize+j*lowmcstatesize, wsize);
            tmpstate[j] = circ->PutXORGate(tmpstate[j], lut[REVERSE_BYTE_ORDER[tmp]]);
        }
    }
    m_linCtr += lowmcstatesize*lowmcstatesize;

    for (i = 0; i < lowmcstatesize; i++)
        state[i] = tmpstate[i];

    free(lut);
}

void LowMCMultiplyStateCallback(vector<uint32_t>& state, uint32_t lowmcstatesize, BooleanCircuit* circ) {
    vector<uint32_t> tmpstate(lowmcstatesize);
    UGATE_T*** fourrussiansmat;

    circ->PutCallbackGate(state, 0, &CallbackBuild4RMatrixAndMultiply, (void*) fourrussiansmat, 1);
    for (uint32_t i = 1; i < lowmcstatesize-1; i++) {
        matmul* mulinfos = (matmul*) malloc(sizeof(matmul));
        mulinfos->column = i;
        //mulinfos->matrix = (UGATE_T) fourrussiansmat;

        tmpstate[i] = circ->PutCallbackGate(state, 0, &CallbackMultiplication, (void*) mulinfos, 1);
    }
    circ->PutCallbackGate(state, 0, &CallbackMultiplyAndDestroy4RMatrix, (void*) fourrussiansmat, 1);


    for (uint32_t i = 0; i < lowmcstatesize; i++)
        state[i] = tmpstate[i];
}

void CallbackMultiplication(GATE* gate, void* matinfos) {
    cout << "Performing multiplication" << endl;
    for(uint32_t i = 0; i < gate->ingates.ningates; i++) {

    }
    //alternatively, check if i == 0 and then call CallbackBuild4RMatrix(gate, matinfos.matrix); and check if i == statesize-1 and delete matrix
    free(matinfos);
}

void CallbackBuild4RMatrixAndMultiply(GATE* gate, void* mat) {
    //for(uint32_t i = 0; i < )
    //TODO
    cout << "Building 4 Russians matrix" << endl;
}

void CallbackMultiplyAndDestroy4RMatrix(GATE* gate, void* matrix) {
    //TODO
}
