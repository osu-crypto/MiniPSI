#pragma once

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "PsiDefines.h"
#include <array>
#include <array>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/Timer.h>
#include "Poly/polyNTL.h"
#include "PsiDefines.h"
#include <NTL/ZZ_p.h>
#include <NTL/vec_ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include <NTL/ZZ.h>
#include "Tools/BalancedIndex.h"
#include "cryptoTools/Crypto/Curve.h"
#include "cryptoTools/Crypto/RandomOracle.h"

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
        std::vector<u64> mIntersection;


		void startPsi(u64 myInputSize, u64 theirInputSize, u64 secParam, block seed, span<block> inputs, span<Channel> chls);
		void startPsi_subsetsum(u64 myInputSize, u64 theirInputSize, u64 secParam, block seed, span<block> inputs, span<Channel> chls);
		bool startPsi_subsetsum_malicious(u64 myInputSize, u64 theirInputSize, u64 secParam, block seed,span<block> inputs, span<Channel> chls);

    };

}