#pragma once

#include "cryptoTools/Common/Defines.h"

#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Crypto/PRNG.h"

namespace osuCrypto
{
    class EcdhPsiSender
    {
    public:
        EcdhPsiSender();
        ~EcdhPsiSender();

		u64 stepSize = 1<<6;

        u64 mN, mSecParam;
        PRNG mPrng;


		void sendInput_k283(span<block> inputs, span<Channel> chl);
		void sendInput_Curve25519(span<block> inputs, span<Channel> chl);
		void sendInput(u64 n, u64 secParam, block seed, span<block> inputs,  span<Channel> chl, int curveType);
        //void sendInput(std::vector<block>& inputs, std::vector<Channel*>& chl);
    };

}