#pragma once

#include "cryptoTools/Common/Defines.h"

#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "PsiDefines.h"
#include "cryptoTools/Common/Timer.h"

namespace osuCrypto
{
    class JL10PsiSender
    {
    public:
        JL10PsiSender();
        ~JL10PsiSender();

		u64 stepSize = 1<< 6;
		Timer timer;

		//u8* mK;
		//u8* mG_K;
        u64 mSecParam;
        PRNG mPrng;

		u64 mMyInputSize, mTheirInputSize,  mStepSize, mPsiSecParam, mFieldSize;

		void startPsi(u64 myInputSize, u64 theirInputSize, u64 secParam, block seed, span<block> inputs, span<Channel> chls);
		void startPsi_subsetsum(u64 myInputSize, u64 theirInputSize, u64 secParam, block seed, span<block> inputs, span<Channel> chls);
		bool startPsi_subsetsum_malicious(u64 myInputSize, u64 theirInputSize, u64 secParam, block seed, span<block> inputs, span<Channel> chls);



    };

}