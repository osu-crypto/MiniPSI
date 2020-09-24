#pragma once
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/Curve.h>
#define NTL_Threads
#define  DEBUG
#include "PsiDefines.h"
#include <NTL/ZZ_p.h>
#include <NTL/vec_ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include <NTL/ZZ.h>
#include <sstream>
#include <string>

using namespace NTL;
#define NTL_Threads_ON
#define PolyNTL_flag
#ifdef _MSC_VER
//#define PSI_PRINT
//#define PRINT
#endif
#define PASS_MIRACL

namespace osuCrypto
{
	
	static const ZZ mPrime128 = to_ZZ("340282366920938463463374607431768211507");
	static const ZZ mPrime160 = to_ZZ("1461501637330902918203684832716283019655932542983");  //nextprime(2^160)
	static const ZZ mPrime164 = to_ZZ("23384026197294446691258957323460528314494920687733");  //nextprime(2^164)
	static const ZZ mPrime168 = to_ZZ("374144419156711147060143317175368453031918731001943");  //nextprime(2^168)
	static const ZZ mPrime172 = to_ZZ("5986310706507378352962293074805895248510699696029801");  //nextprime(2^172)
	static const ZZ mPrime176 = to_ZZ("95780971304118053647396689196894323976171195136475563");  //nextprime(2^176)
	static const ZZ mPrime180 = to_ZZ("1532495540865888858358347027150309183618739122183602191");  //nextprime(2^180)
	static const ZZ mPrime184 = to_ZZ("24519928653854221733733552434404946937899825954937634843");  //nextprime(2^184)
	static const ZZ mPrime188 = to_ZZ("392318858461667547739736838950479151006397215279002157113");  //nextprime(2^188)
	static const ZZ mPrime264 = to_ZZ("29642774844752946028434172162224104410437116074403984394101141506025761187823791");  //nextprime(2^264)
	static const ZZ mPrime255_19 = to_ZZ("57896044618658097711785492504343953926634992332820282019728792003956564819949");  //nextprime(2^264)
	static const ZZ mPrime256 = to_ZZ("115792089237316195423570985008687907853269984665640564039457584007913129640233");  //nextprime(2^264)
	static const ZZ mPrime224 = to_ZZ("26959946667150639794667015087019630673637144422540572481103610249951");  //nextprime(2^264)


	//static const Ecc2mParams myEccpParams = k283;
	static const EccpParams myEccpParams = Curve25519;
	static const ZZ myPrime= mPrime264;


	static const u8 mMiniPolySlices(2); //2*128 
	static const u64 stepSize(1 << 2);
	static const u64 numStep(1 << 2);
	static const u64 stepSizeMaskSent(1<<11);
//	static const u8 numSuperBlocks(4); //wide of T (or field size) 
	static const u8 numSuperBlocks(3); //wide of T (or field size)  =3 for HD-PSI


	static const u8 first2Slices(2); //2*128 + (436-2*128)
	static const u64 recvNumDummies(1);
	static const u64 recvMaxBinSize(40);
	static std::vector<block> mOneBlocks(128); 
	static const u64 primeLong(129);
	static const u64 fieldSize(440); //TODO 4*sizeof(block)

	static const u64 bIdxForDebug(3), iIdxForDebug(0), hIdxForDebug(0);

		
	inline void getExpParams(u64 setSize, u64& numSeeds, u64& numChosen)
	{

		if (setSize <= (1 << 8))
		{
			numSeeds = 1<<7;
			numChosen = 23;
		}
		else if (setSize <= (1 << 10))
		{
			numSeeds = 1<<7;
			numChosen = 24;
		}
		else if (setSize <= (1 << 12))
		{
			numSeeds = 1<<7;
			numChosen = 25;
		}
		else if (setSize <= (1 << 14))
		{
			numSeeds = 1<<8;
			numChosen = 20;
		}
		else if (setSize <= (1 << 16))
		{
			numSeeds = 1<<9;
			numChosen = 17;
		}
		else if (setSize <= (1 << 18))
		{
			numSeeds = 1<<10;
			numChosen = 15;
		}
		else if (setSize <= (1 << 20))
		{
			numSeeds = 1<<13;
			numChosen = 11;
		}
		else if (setSize <= (1 << 22))
		{
			numSeeds = 1<<14;
			numChosen = 11;
		}
		else if (setSize <= (1 << 24))
		{
			numSeeds = 1<<15;
			numChosen = 10;
		}
	}



	inline void getBestExpParams(u64 setSize, u64& numSeeds, u64& numChosen, u64& boundCoeff)
	{

		if (setSize <= (1 << 5))
		{
			numSeeds = 1<<5;
			numChosen = 19;
			boundCoeff = 1 << 4;

		}
		else if (setSize <= (1 << 10))
		{
			numSeeds = 1 << 7;
			numChosen = 24;
			boundCoeff = 1 << 1;
		}
		else if (setSize <= (1 << 12))
		{
			numSeeds = 1 << 7;
			numChosen = 25;
			boundCoeff = 1 << 1;
		}
		else if (setSize <= (1 << 14))
		{
			numSeeds = 1 << 8;
			numChosen = 20;
			boundCoeff = 1 << 1;
		}
		else if (setSize <= (1 << 16))
		{
			numSeeds = 1 << 9;
			numChosen = 17;
			boundCoeff = 1 << 1;
		}
		else if (setSize <= (1 << 18))
		{
			numSeeds = 1 << 10;
			numChosen = 15;
			boundCoeff = 1 << 1;
		}
		else if (setSize <= (1 << 20))
		{
			numSeeds = 1 << 13;
			numChosen = 11;
			boundCoeff = 1 << 1;
		}
		else if (setSize <= (1 << 22))
		{
			numSeeds = 1 << 14;
			numChosen = 11;
			boundCoeff = 1 << 1;
		}
		else if (setSize <= (1 << 24))
		{
			numSeeds = 1 << 15;
			numChosen = 10;
			boundCoeff = 1 << 1;
		}
	}

	struct RecExpParams
	{
		u32 numSeeds;
		u32 numChosen;
		u32 boundCoeff;
		u64 numNewSeeds;
	};

	inline void getBestH1RecurrExpParams(u64 setSize, std::vector<RecExpParams>& mSeq)
	{
		if (setSize <= (1 << 8))
		{
			mSeq.resize(1);
			mSeq[0] = { 1 << 7, 23, 1 << 1,setSize }; 
		}
		else if (setSize <= (1 << 10))
		{
			mSeq.resize(2);
			mSeq[0] = { 1 << 7, 23, 1 << 1,setSize };
			mSeq[1] = { 1 << 8, 19, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 12))
		{
			mSeq.resize(2);
			mSeq[0] = { 1 << 7, 24, 1 << 1,setSize };
			mSeq[1] = { 1 << 9, 16, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 14))
		{
			mSeq.resize(3);
			mSeq[0] = { 1 << 7, 25, 1 << 1,setSize };
			mSeq[1] = { 1 << 9, 16, 1 << 1,setSize };
			mSeq[2] = { 1 << 11, 13, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 16))
		{
			mSeq.resize(4);
			mSeq[0] = { 1 << 7, 24, 1 << 1,setSize };
			mSeq[1] = { 1 << 8, 19, 1 << 1,setSize };
			mSeq[2] = { 1 << 10, 15, 1 << 1,setSize };
			mSeq[3] = { 1 << 13, 11, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 18))
		{
			mSeq.resize(4);
			mSeq[0] = { 1 << 7, 25, 1 << 1,setSize };
			mSeq[1] = { 1 << 9, 16, 1 << 1,setSize };
			mSeq[2] = { 1 << 11, 13, 1 << 1,setSize };
			mSeq[3] = { 1 << 16, 9, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 20))
		{
			mSeq.resize(4);
			mSeq[0] = { 1 << 7, 26, 1 << 1,setSize };
			mSeq[1] = { 1 << 10, 15, 1 << 1,setSize };
			mSeq[2] = { 1 << 13, 11, 1 << 1,setSize };
			mSeq[3] = { 1 << 16, 9, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 22))
		{
			mSeq.resize(5);
			mSeq[0] = { 1 << 7, 26, 1 << 1,setSize };
			mSeq[1] = { 1 << 10, 15, 1 << 1,setSize };
			mSeq[2] = { 1 << 13, 11, 1 << 1,setSize };
			mSeq[3] = { 1 << 16, 9, 1 << 1,setSize };
			mSeq[4] = { 1 << 19, 8, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 24))
		{
			mSeq.resize(5);
			mSeq[0] = { 1 << 7, 26, 1 << 1,setSize };
			mSeq[1] = { 1 << 10, 15, 1 << 1,setSize };
			mSeq[2] = { 1 << 13, 11, 1 << 1,setSize };
			mSeq[3] = { 1 << 16, 9, 1 << 1,setSize };
			mSeq[4] = { 1 << 19, 8, 1 << 1,setSize };
		}
	}


	inline void getBestRecurrExpParams(u64 setSize, std::vector<RecExpParams>& mSeq)
	{
		if (setSize <= (1 << 8))
		{
			mSeq.resize(3);
			//mSeq[0] = { 1 << 1, 1, 1 << 104,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[0] = { 1 << 1, 1, 1 << 10,setSize }; //implement 1<<128, instead of 1 << 104
			mSeq[1] = { 1 << 6, 25, 1 << 2,setSize };
			mSeq[2] = { 1 << 7, 24, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 10))
		{
			mSeq.resize(4);
			//mSeq[0] = { 1 << 1, 1, 1 << 104,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[0] = { 1 << 1, 1, 1 << 10,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[1] = { 1 << 6, 25, 1 << 2,setSize };
			mSeq[2] = { 1 << 7, 24, 1 << 1,setSize };
			mSeq[3] = { 1 << 8, 19, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 12))
		{
			mSeq.resize(5);
			//mSeq[0] = { 1 << 1, 1, 1 << 106,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[0] = { 1 << 1, 1, 1 << 10,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[1] = { 1 << 6, 25, 1 << 2,setSize };
			mSeq[2] = { 1 << 7, 24, 1 << 1,setSize };
			mSeq[3] = { 1 << 8, 19, 1 << 1,setSize };
			mSeq[4] = { 1 << 10, 14, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 14))
		{
			mSeq.resize(5);
			//mSeq[0] = { 1 << 1, 1, 1 << 106,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[0] = { 1 << 1, 1, 1 << 10,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[1] = { 1 << 6, 25, 1 << 2,setSize };
			mSeq[2] = { 1 << 7, 25, 1 << 1,setSize };
			mSeq[3] = { 1 << 8, 20, 1 << 1,setSize };
			mSeq[4] = { 1 << 11, 13, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 16))
		{
			mSeq.resize(5);
			//mSeq[0] = { 1 << 1, 1, 1 << 106,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[0] = { 1 << 1, 1, 1 << 10,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[1] = { 1 << 6, 25, 1 << 2,setSize };
			mSeq[2] = { 1 << 7, 26, 1 << 1,setSize };
			mSeq[3] = { 1 << 10, 15, 1 << 1,setSize };
			mSeq[4] = { 1 << 13, 11, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 18))
		{
			mSeq.resize(6);
		//	mSeq[0] = { 1 << 1, 1, 1 << 106,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[0] = { 1 << 1, 1, 1 << 10,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[1] = { 1 << 6, 25, 1 << 2,setSize };
			mSeq[2] = { 1 << 7, 25, 1 << 1,setSize };
			mSeq[3] = { 1 << 9, 17, 1 << 1,setSize };
			mSeq[4] = { 1 << 12, 12, 1 << 1,setSize };
			mSeq[5] = { 1 << 15, 10, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 20))
		{
			mSeq.resize(6);
			//mSeq[0] = { 1 << 1, 1, 1 << 106,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[0] = { 1 << 1, 1, 1 << 10,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[1] = { 1 << 6, 25, 1 << 2,setSize };
			mSeq[2] = { 1 << 7, 26, 1 << 1,setSize };
			mSeq[3] = { 1 << 10, 15, 1 << 1,setSize };
			mSeq[4] = { 1 << 13, 11, 1 << 1,setSize };
			mSeq[5] = { 1 << 16, 9, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 22))
		{
			mSeq.resize(7);
			//mSeq[0] = { 1 << 1, 1, 1 << 106,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[0] = { 1 << 1, 1, 1 << 10,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[1] = { 1 << 6, 25, 1 << 2,setSize };
			mSeq[2] = { 1 << 7, 26, 1 << 1,setSize };
			mSeq[3] = { 1 << 10, 15, 1 << 1,setSize };
			mSeq[4] = { 1 << 13, 11, 1 << 1,setSize };
			mSeq[5] = { 1 << 16, 9, 1 << 1,setSize };
			mSeq[6] = { 1 << 19, 8, 1 << 1,setSize };
		}
		else if (setSize <= (1 << 24))
		{
			mSeq.resize(7);
			//mSeq[0] = { 1 << 1, 1, 1 << 106,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[0] = { 1 << 1, 1, 1 << 10,setSize }; //numSeeds,numChosen,boundCoeff
			mSeq[1] = { 1 << 6, 25, 1 << 2,setSize };
			mSeq[2] = { 1 << 7, 26, 1 << 1,setSize };
			mSeq[3] = { 1 << 10, 15, 1 << 1,setSize };
			mSeq[4] = { 1 << 13, 11, 1 << 1,setSize };
			mSeq[5] = { 1 << 16, 9, 1 << 1,setSize };
			mSeq[6] = { 1 << 19, 8, 1 << 1,setSize };
		}
	}


	inline const char* tostr(int x)
	{
			std::stringstream str;
			str << x;
			return str.str().c_str();
	}


	inline u64 getFieldSizeInBits(u64 setSize)
	{

		if (setSize <= (1 << 10))
			return 416;
		else if (setSize <= (1 << 12))
			return 420;
		else if (setSize <= (1 << 14))
			return 424;
		else if (setSize <= (1 << 16))
			return 428;
		else if (setSize <= (1 << 18))
			return 432;
		else if (setSize <= (1 << 20))
			return 436;
		else if (setSize <= (1 << 22))
			return 436;
		else if (setSize <= (1 << 24))
			return 444;

		return 444;
	}


	inline ZZ getPrimeLastSlice(u64 fieldSize)
	{
		u64 lastBit = fieldSize - 2 * 128;
		if (lastBit==160)
			return mPrime160;
		else if (lastBit == 164)
			return mPrime164;
		else if (lastBit == 168)
			return mPrime168;
		else if (lastBit == 172)
			return mPrime172;
		else if (lastBit == 176)
			return mPrime176;
		else if (lastBit == 180)
			return mPrime180;
		else if (lastBit == 184)
			return mPrime184;
		else if (lastBit == 188)
			return mPrime188;
		
		return mPrime188;
	}


	
	struct item
	{
		u64 mHashIdx;
		u64 mIdx;
	};


	static __m128i mm_bitshift_right(__m128i x, unsigned count)
	{
		__m128i carry = _mm_slli_si128(x, 8);   // old compilers only have the confusingly named _mm_slli_si128 synonym
		if (count >= 64)
			return _mm_slli_epi64(carry, count - 64);  // the non-carry part is all zero, so return early
													   // else
		return _mm_or_si128(_mm_slli_epi64(x, count), _mm_srli_epi64(carry, 64 - count));

	}


	static __m128i mm_bitshift_left(__m128i x, unsigned count)
	{
		__m128i carry = _mm_srli_si128(x, 8);   // old compilers only have the confusingly named _mm_slli_si128 synonym
		if (count >= 64)
			return _mm_srli_epi64(carry, count - 64);  // the non-carry part is all zero, so return early

		return _mm_or_si128(_mm_srli_epi64(x, count), _mm_slli_epi64(carry, 64 - count));
	}

	inline void fillOneBlock(std::vector<block>& blks)
	{
		for (int i = 0; i < blks.size(); ++i)
			blks[i] = mm_bitshift_right(OneBlock, i);
	}

	static void prfOtRows(std::vector<block>& inputs,  std::vector<std::array<block, numSuperBlocks>>& outputs, std::vector<AES>& arrAes)
	{
		std::vector<block> ciphers(inputs.size());
		outputs.resize(inputs.size());

		for (int j = 0; j < numSuperBlocks - 1; ++j) //1st 3 blocks
			for (int i = 0; i < 128; ++i) //for each column
			{
				arrAes[j * 128 + i].ecbEncBlocks(inputs.data(), inputs.size(), ciphers.data()); //do many aes at the same time for efficeincy

				for (u64 idx = 0; idx < inputs.size(); idx++)
				{
					ciphers[idx] = ciphers[idx]&mOneBlocks[i];
					outputs[idx][j] = outputs[idx][j] ^ ciphers[idx];
				}
			}

		
		int j = numSuperBlocks - 1;
		for (int i = j * 128; i < arrAes.size(); ++i)
		{
				arrAes[i].ecbEncBlocks(inputs.data(), inputs.size(), ciphers.data()); //do many aes at the same time for efficeincy
				for (u64 idx = 0; idx < inputs.size(); idx++)
				{
					ciphers[idx] = ciphers[idx] & mOneBlocks[i-j*128];
					outputs[idx][j] = outputs[idx][j] ^ ciphers[idx];
				}
			
		}

	}

	static void prfOtRow(block& input, std::array<block, numSuperBlocks>& output, std::vector<AES> arrAes, u64 hIdx=0)
	{
		block cipher;

		for (int j = 0; j < numSuperBlocks - 1; ++j) //1st 3 blocks
			for (int i = 0; i < 128; ++i) //for each column
			{
				if(hIdx==1)
					arrAes[j * 128 + i].ecbEncBlock(input^OneBlock, cipher);
				else
					arrAes[j * 128 + i].ecbEncBlock(input, cipher);

				cipher= cipher& mOneBlocks[i];
				output[j] = output[j] ^ cipher;
			}


		int j = numSuperBlocks - 1;
		for (int i = 0; i < 128; ++i)
		{
			if (j * 128 + i < arrAes.size()) {

				if (hIdx == 1)
					arrAes[j * 128 + i].ecbEncBlock(input^OneBlock, cipher);
				else
					arrAes[j * 128 + i].ecbEncBlock(input, cipher);
				
				cipher = cipher& mOneBlocks[i];
				output[j] = output[j] ^ cipher;
			}
			else {
				break;
			}
		}

		//std::cout << IoStream::lock;
		//std::cout << "\t output " << output[0] << "\n";
		//std::cout << IoStream::unlock;

	}

	inline void printArrU8(u8* Z, int size) {

		for (int i = 0; i < size; i++)
			std::cout << static_cast<unsigned int>(Z[i]);

		std::cout << std::endl;
	}
}
