#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.  
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Network/Channel.h>
#include "Poly/polyNTL.h"
#include "PsiDefines.h"
#include <NTL/ZZ_p.h>
#include <NTL/vec_ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include <NTL/ZZ.h>
#include "Poly/polyFFT.h"
#include "Tools/SimpleIndex.h"
#include "cryptoTools/Crypto/Curve.h"
#include "cryptoTools/Crypto/RandomOracle.h"

#include <array>
namespace osuCrypto {

	class MiniSender :public TimerAdapter
	{
	public:
		SimpleIndex simple;

		Ecc2mParams mCurveParam;
		block mCurveSeed;

		u8* mK; 
		u8* mG_K;

		//bool mHasBase;
		u64 mMyInputSize, mTheirInputSize, mPolyBytes, mPolyDegree, mStepSize, mPsiSecParam, mFieldSize;
		PRNG mPrng;
		ZZ mPrime;
		u8* mK_bytes;

		void outputBigPoly(u64 myInputSize, u64 theirInputSize, u64 psiSecParam, PRNG& prng, span<block> inputs, span<Channel> chls);
		void outputHashing(u64 myInputSize, u64 theirInputSize, u64 psiSecParam, PRNG& prng, span<block> inputs, span<Channel> chls);
		void outputSimpleHashing(u64 myInputSize, u64 theirInputSize, u64 psiSecParam, PRNG& prng, span<block> inputs, span<Channel> chls);
		
		bool outputBigPoly_malicious(u64 myInputSize, u64 theirInputSize, u64 psiSecParam, PRNG& prng, span<block> inputs, span<Channel> chls);

		/////*void output(span<block> inputs, span<Channel> chls);
		////void outputBestComm(span<block> inputs, span<Channel> chls);*/
		//void outputBigPoly(span<block> inputs, span<Channel> chls);

	};
}

