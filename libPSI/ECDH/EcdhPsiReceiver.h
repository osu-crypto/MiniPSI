#pragma once

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "../PsiDefines.h"


namespace osuCrypto
{

    class EcdhPsiReceiver
    {
    public:
        EcdhPsiReceiver();
        ~EcdhPsiReceiver();

		u64 myStepSize;
		u64 theirStepSize;
        u64 mN, mSecParam;
        PRNG mPrng;
		u64 mTheirInputSize;

        std::vector<u64> mIntersection;

		void sendInput_k283(span<block> inputs, span<Channel> chls);
        void sendInput_Curve25519(span<block> inputs, span<Channel> chls);
        void sendInput_Ristretto(span<block> inputs, span<Channel> chls);
        void sendInput(u64 n, u64 theirInputSize, u64 secParam, block seed, span<block> inputs, span<Channel> chl0,int curveType);

    };

}