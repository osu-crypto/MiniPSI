#include "SimpleIndex.h"
#include "cryptoTools/Crypto/sha1.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <random>
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/CuckooIndex.h"
#include <numeric>
//#include <boost/math/special_functions/binomial.hpp>
//#include <boost/multiprecision/cpp_bin_float.hpp>

namespace osuCrypto
{


    void SimpleIndex::print(span<block> items)
    {
		std::cout << "mNumDummies=" << mNumDummies << std::endl;
		std::cout << "mNumBins=" << mNumBins << std::endl;
        for (u64 i = 0; i < mBins.size(); ++i)
        {
            std::cout << "SBin #" << i <<  " contains " << mBins[i].blks.size() << " elements" << std::endl;

			for (u64 j = 0; j < mBins[i].blks.size(); j++)
					std::cout << "\t" << mBins[i].blks[j] << "\t" << mBins[i].hashIdxs[j]<< std::endl;
			
            std::cout << std::endl;
        }

        std::cout << std::endl;
    }

    void SimpleIndex::init(u64 theirInputSize, u64 theirMaxBinSize, u64 theirNumDummies, u64 statSecParam)
    {
		mNumBins = 1 + theirInputSize / (theirMaxBinSize - theirNumDummies);
		mTheirMaxBinSize = theirMaxBinSize;
		mHashSeed = _mm_set_epi32(4253465, 3434565, 234435, 23987025); //hardcode hash
		mAesHasher.setKey(mHashSeed);
		mBins.resize(mNumBins);
    }




	u64 SimpleIndex::get_bin_size(u64 numBins, u64 numBalls, u64 statSecParam)
	{
		u64 bin_ball[18][26] = { 
			{ 8,256,184,117,76,51,36,26,20,16,13,11,9,8,7,6,6,5,5,5,4,4,4,4,3,3 },
			{ 9,512,336,203,125,80,53,37,27,21,16,13,11,9,8,7,7,6,5,5,5,4,4,4,4,3 },
			{ 10,1024,626,360,212,129,82,54,38,28,21,17,13,11,10,8,7,7,6,6,5,5,4,4,4,4 },
			{ 11,2048,1185,658,372,217,131,83,55,38,28,21,17,14,11,10,9,8,7,6,6,5,5,5,4,4 },
			{ 12,4096,2276,1229,673,379,220,133,84,56,39,28,22,17,14,12,10,9,8,7,6,6,5,5,5,4 },
			{ 13,8192,4419,2336,1250,682,383,222,134,85,56,39,29,22,17,14,12,10,9,8,7,6,6,5,5,5 },
			{ 14,16384,8649,4501,2365,1262,688,386,224,135,86,57,40,29,22,18,14,12,10,9,8,7,6,6,5,5 },
			{ 15,32768,17030,8764,4541,2381,1269,692,388,225,136,86,57,40,29,22,18,15,12,10,9,8,7,7,6,6 },
			{ 16,65536,33682,17191,8819,4564,2391,1274,695,390,227,137,87,58,41,30,23,18,15,12,11,9,8,7,7,6 },
			{ 17,131072,66829,33907,17268,8850,4578,2399,1279,697,392,228,138,88,59,41,30,23,18,15,13,11,9,8,7,7 },
			{ 18,262144,132901,67145,34016,17312,8870,4588,2404,1282,700,393,229,139,88,59,41,30,23,18,15,13,11,10,8,8 },
			{ 19,524288,264730,133346,67298,34077,17339,8884,4596,2409,1285,702,395,230,140,89,60,42,31,24,19,15,13,11,10,9 },
			{ 20,1048576,527945,265357,133561,67384,34116,17359,8895,4603,2414,1289,704,396,231,141,90,60,42,31,24,19,16,13,11,10 },
			{ 21,2097152,1053748,528831,265662,133682,67438,34143,17375,8905,4609,2418,1292,706,398,232,142,90,61,43,31,24,19,16,13,11 },
			{ 22,4194304,2104466,1054998,529260,265832,133758,67477,34165,17388,8914,4615,2422,1295,708,400,234,143,91,61,43,32,24,19,16,13 },
			{ 23,8388608,4204646,2106232,1055604,529500,265940,133813,67508,34184,17400,8922,4621,2426,1298,711,401,235,143,92,62,43,32,25,20,16 },
			{ 24,16777216,8403233,4207142,2107088,1055944,529652,266016,133856,67534,34201,17412,8930,4627,2430,1300,713,403,236,144,92,62,44,32,25,20 },
			};

			int idxBin = log2(numBalls) ;
			if (idxBin != bin_ball[idxBin-8][0])
			{
				std::cout << "idxBin != bin_ball[idxBin][0] \t "<< idxBin << " vs " << bin_ball[idxBin-8][0] <<"\n";
				throw std::runtime_error("");
			}

			int logNumBin;

			if (numBins == 0)
				return numBalls;
			else
				logNumBin = log2(numBins);


		return bin_ball[idxBin-8][logNumBin+1];
	}

	
    void SimpleIndex::insertItems(span<block> items)
    {
		
		block cipher;
		u64 b1, b2; //2 bins index

		//1st pass
		for (u64 idxItem = 0; idxItem < items.size(); ++idxItem)
		{
			cipher = mAesHasher.ecbEncBlock(items[idxItem]);

			b1 = _mm_extract_epi64(cipher, 0) % mNumBins; //1st 64 bits for finding bin location
			b2 = _mm_extract_epi64(cipher, 1) % mNumBins; //2nd 64 bits for finding alter bin location
						

			mBins[b1].blks.push_back(items[idxItem]);
			mBins[b2].blks.push_back(items[idxItem]);

			mBins[b1].hashIdxs.push_back(0);
			mBins[b2].hashIdxs.push_back(1);

			mBins[b1].Idxs.push_back(idxItem);
			mBins[b2].Idxs.push_back(idxItem);

				
		}
	}

	void SimpleIndex::initOneHash(u64 myInputsize, u64 theirInputSize, u64 numsBin,  u64 statSecParam)
	{
		mTheirMaxBinSize = get_bin_size(numsBin, theirInputSize, statSecParam);
		mMyMaxBinSize = get_bin_size(numsBin, myInputsize, statSecParam);

		mNumBins = numsBin;
		mHashSeed = _mm_set_epi32(4253465, 3434565, 234435, 23987025); //hardcode hash
		mAesHasher.setKey(mHashSeed);
		mBins.resize(mNumBins);
	}

	void SimpleIndex::insertItemsOneHash(span<block> items)
	{

		block cipher;
		u64 b1, b2; //2 bins index

					//1st pass
		for (u64 idxItem = 0; idxItem < items.size(); ++idxItem)
		{
			cipher = mAesHasher.ecbEncBlock(items[idxItem]);

			b1 = _mm_extract_epi64(cipher, 0) % mNumBins; //1st 64 bits for finding bin location

			mBins[b1].blks.push_back(items[idxItem]);
			mBins[b1].hashIdxs.push_back(0);
			mBins[b1].Idxs.push_back(idxItem);


		}
	}

}
