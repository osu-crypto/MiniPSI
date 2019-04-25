#pragma once

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "PsiDefines.h"

namespace osuCrypto
{

    class JL10PsiReceiver
    {
    public:
        JL10PsiReceiver();
        ~JL10PsiReceiver();

		u64 stepSize = 1<<6;
        u64 mN, mSecParam;
        PRNG mPrng;

		u64 mSetSeedsSize, mChoseSeedsSize, mMyInputSize, mTheirInputSize, mFieldSize;
		block mCurveSeed;
		std::vector<u8*> mSeeds; //all ri in bytes for computing (g^k)^(ri) later
		std::vector<u8*> mG_seeds;

        std::vector<u64> mIntersection;

		//Timer timer;


        void init(u64 myInputSize, u64 theirInputSize, u64 secParam, block seed);
		void sendInput_k283(span<block> inputs, span<Channel> chls);

    };

}