#include "MiniReceiver_Ris.h"

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/Commit.h>
#include <cryptoTools/Network/Channel.h>
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"
#include "Poly/polyFFT.h"
#include <set>
#include <cryptoTools/Crypto/Rijndael256.h>


using namespace std;
using namespace NTL;

namespace osuCrypto
{


	void MiniReceiver_Ris::expTinvert(u64 myInputSize, u64 psiSecParam, PRNG& prng)
	{
		mMyInputSize = myInputSize;
		//2*number of group needded for T^-1
		getBestExpParams(mMyInputSize, mSetSeedsSize, mChoseSeedsSize, mBoundCoeffs);

		std::cout << "r mSetSeedsSize= " << mMyInputSize << " - " << mSetSeedsSize << " - " << mChoseSeedsSize << "\n";

		//seed for subset-sum exp
		EllipticCurve mCurve(myEccpParams, OneBlock);

		EccPoint mG(mCurve);
		mG = mCurve.getGenerator();

		std::vector<EccNumber> nSeeds;
		std::vector<EccPoint> pG_seeds;
		nSeeds.reserve(mSetSeedsSize);
		pG_seeds.reserve(mSetSeedsSize);
		
		//seeds
		for (u64 i = 0; i < mSetSeedsSize; i++)
		{
			// get a random value from Z_p
			nSeeds.emplace_back(mCurve);
			nSeeds[i].randomize(prng);
			pG_seeds.emplace_back(mCurve);
			pG_seeds[i] = mG * nSeeds[i];  //g^ri
		}


		std::set<u64> indices;
		mIntCi.resize(mMyInputSize);

		gTimer.reset();
		gTimer.setTimePoint("Tinvert start");

		int cnt_call_T_invert = 0;
		int cnt_call_PI_invert = 0;

		for (u64 i = 0; i < myInputSize; i++)
		{
			std::vector<u8*> buffs;
			do {

				EccPoint g_sum(mCurve);
				indices.clear();
				while (indices.size() < mChoseSeedsSize)
					indices.insert(rand() % mSetSeedsSize);

				if (mBoundCoeffs == 2)
				{
					//for (u64 j = 0; j < mChoseSeedsSize; j++)
					for (auto it = indices.begin(); it != indices.end(); ++it)
						g_sum = g_sum + pG_seeds[*it]; //g^sum //h=2   ci=1
				}
				else
				{
					mIntCi[i].resize(mChoseSeedsSize);

					int j = 0;
					for (auto it = indices.begin(); it != indices.end(); ++it)
					{
						mIntCi[i][j] = 1 + rand() % (mBoundCoeffs - 1);
						EccNumber ci(mCurve, mIntCi[i][j]);
						g_sum = g_sum + pG_seeds[*it] * ci; //g^ci*sum
						j++;
					}
				}

				buffs.clear();
				cnt_call_PI_invert +=ropoGroup2Field(mCurve, g_sum, buffs);
				cnt_call_T_invert++;
			} while (buffs.size() == 0);
		}
	
		gTimer.setTimePoint("Tinvert done");
		std::cout << "#cnt_call_Tinvert: " << cnt_call_T_invert << "\t | \t";
		std::cout << "#cnt_call_PI_invert: " << cnt_call_PI_invert << "\n";
		std::cout << gTimer << std::endl;
	}


	void MiniReceiver_Ris::outputBigPoly(u64 myInputSize, u64 theirInputSize, u64 psiSecParam, PRNG & prng, span<block> inputs, span<Channel> chls)
	{
		for (u64 i = 0; i < chls.size(); ++i)
		{
			u8 dummy[1];
			chls[i].asyncSend(dummy, 1);
			chls[i].recv(dummy, 1);
			chls[i].resetStats();
		}
		gTimer.reset();
		//####################### offline #########################
		gTimer.setTimePoint("r offline start ");

		ropo_fe25519_1(mfe25519_one);
		mPsiSecParam = psiSecParam;
		mMyInputSize = myInputSize;
		mTheirInputSize = theirInputSize;
		mPrng.SetSeed(prng.get<block>());
		
		//2*number of group needded for T^-1
		getBestExpParams(2*mMyInputSize, mSetSeedsSize, mChoseSeedsSize, mBoundCoeffs);

		std::cout << "r mSetSeedsSize= " << mMyInputSize << " - " << mSetSeedsSize << " - " << mChoseSeedsSize << "\n";

		mFieldSize = crypto_core_ristretto255_BYTES;
		mPolyBytes = mFieldSize;
		mCurveByteSize = mFieldSize;

#ifdef MINI_PSI_Subsetsum
		std::cout << "MINI_PSI_Subsetsum: Yes \n";
		std::vector<unsigned char*> nSeeds(mSetSeedsSize); //number
		std::vector<unsigned char*> pG_seeds(mSetSeedsSize); //g^num


			//seeds
		for (u64 i = 0; i < mSetSeedsSize; i++)
		{
			// get a random value from Z_p
			nSeeds[i] = new unsigned char[crypto_core_ristretto255_SCALARBYTES];
			crypto_core_ristretto255_scalar_random(nSeeds[i]);

			//      pG_seeds[i] = g ^ mSeeds[i]
			pG_seeds[i] = new unsigned char[crypto_core_ristretto255_BYTES];;  //g^ri
			crypto_scalarmult_ristretto255_base(pG_seeds[i], nSeeds[i]);
			//std::cout << mG_seeds[i] << std::endl;
		}
		std::cout << "pG_seeds done" << std::endl;
		gTimer.setTimePoint("r off pG_seeds done");

		//generate all pairs from seeds
		std::vector<std::pair<std::set<u64>, unsigned char*>> mG_pairs_subsetsum; //{index of sub ri}, g^(subsum ri)
		mG_pairs_subsetsum.reserve(myInputSize);

		std::set<u64> indices;
		
		mIntCi.resize(mMyInputSize);

		for (u64 i = 0; i < myInputSize; i++)
		{
			
			std::vector<unsigned char*> buffs;

			unsigned char g_sum[crypto_core_ristretto255_BYTES] = {};

			do {

				indices.clear();
				while (indices.size() < mChoseSeedsSize)
					indices.insert(rand() % mSetSeedsSize);


				/*ri[i] = 0;
				for (u64 j = 0; j < mChoseSeedsSize; j++)
					ri[i] = ri[i] + nSeeds[indices[j]];*/

				if (mBoundCoeffs == 2) //most cases
				{
					//for (u64 j = 0; j < mChoseSeedsSize; j++)
					for (auto it = indices.begin(); it != indices.end(); ++it)
						crypto_core_ristretto255_add(g_sum, g_sum, pG_seeds[*it]); //g^sum //h=2   ci=1
				}
				else
				{
					std::cout << "mBoundCoeffs Don't support\n";
					throw std::runtime_error("rt error at " LOCATION);
					//mIntCi[i].resize(mChoseSeedsSize);

					//int j = 0;
					//for (auto it = indices.begin(); it != indices.end(); ++it)
					//{
					//	mIntCi[i][j] = 1 + rand() % (mBoundCoeffs - 1);

					//	EccNumber ci(mCurve, mIntCi[i][j]);
					//	g_sum = g_sum + pG_seeds[*it] * ci; //g^ci*sum
					//	j++;
					//}
				}
				//g_sum = mG * ri[i];
				

				buffs.clear();
				ristretto_ropoGroup2Field(g_sum, buffs, mfe25519_one);
			} while (buffs.size() ==0);
			
#ifdef DEBUG_MINI_PSI_RIS
			std::cout << toBlock((u8*)&g_sum) << "\t r orignial point#######\n";
#endif // DEBUG_MINI_PSI_RIS

			int rand_idx = rand() % buffs.size(); //choose random si
			mG_pairs_subsetsum.push_back(std::make_pair(indices, buffs[rand_idx]));

			/*unsigned char* point_ri = new unsigned char[crypto_core_ristretto255_BYTES];
			ristretto_ropoField2Group(buffs[rand_idx], point_ri, mfe25519_one);
			std::cout << "rrr point_ri= " << toBlock((u8*)point_ri) << "\n";*/
		}
#else
		mScalars.resize(myInputSize);

		for (u64 i = 0; i < myInputSize; i++)
		{

			std::vector<unsigned char*> buffs;

			unsigned char g_sum[crypto_core_ristretto255_BYTES] = {};
			mScalars[i]=new unsigned char[crypto_core_ristretto255_SCALARBYTES];

			do {
				buffs.clear();
				
				crypto_core_ristretto255_scalar_random(mScalars[i]);
				crypto_scalarmult_ristretto255_base(g_sum, mScalars[i]);
				ristretto_ropoGroup2Field(g_sum, buffs, mfe25519_one);

			} while (buffs.size() == 0);

			int rand_idx = rand() % buffs.size(); //choose random si
			mG_pairs.push_back(buffs[rand_idx]);


#ifdef DEBUG_MINI_PSI_RIS
			std::cout << toBlock((u8*)&g_sum) << "\t r orignial point#######\n";
			unsigned char* point_ri = new unsigned char[crypto_core_ristretto255_BYTES];
			ristretto_ropoField2Group(buffs[rand_idx], point_ri, mfe25519_one);
			std::cout << "rrr point_ri= " << toBlock((u8*)point_ri) << "\n";
#endif // DEBUG_MINI_PSI_RIS

		}
#endif
		
		std::cout << "r mG_pairs done" << std::endl;

		//####################### online #########################
		gTimer.setTimePoint("r online start ");

		unsigned char g_k[crypto_core_ristretto255_BYTES];
		chls[0].recv(g_k); //receiving g^k
		//std::cout << "r g^k= " << toBlock((u8*)&g_k) << std::endl;


		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;
		std::vector<std::thread> thrds(numThreads);
		std::mutex mtx;

		u64 n1n2MaskBits = 2*128;// (40 + log2(mTheirInputSize*mMyInputSize));
		u64 n1n2MaskBytes = (n1n2MaskBits + 7) / 8;



#if 1
		//#####################Poly#####################
		mPrime = myPrime;
		ZZ_p::init(ZZ(mPrime));

		u64 degree = inputs.size() - 1;
		ZZ_p* zzX = new ZZ_p[inputs.size()];
		ZZ_p* zzY = new ZZ_p[inputs.size()];

		ZZ zz;
		ZZ_pX *M = new ZZ_pX[degree * 2 + 1];;
		ZZ_p *a = new ZZ_p[degree + 1];;
		ZZ_pX* temp = new ZZ_pX[degree * 2 + 1];
		ZZ_pX Polynomial;
		std::vector<u8> sendBuff;


		for (u64 idx = 0; idx < inputs.size(); idx++)
		{
			ZZFromBytes(zz, (u8*)&inputs[idx], sizeof(block));
			zzX[idx] = to_ZZ_p(zz);

			u8* yri = new u8[mPolyBytes];

#ifdef MINI_PSI_Subsetsum

			ZZFromBytes(zz, mG_pairs_subsetsum[idx].second, mPolyBytes);
			
#ifdef DEBUG_MINI_PSI_RIS
			std::cout << idx << " r P(x)= " << toBlock((u8*)mG_pairs_subsetsum[idx].second) 
				<< " - " << toBlock(mG_pairs_subsetsum[idx].second + sizeof(block)) << std::endl;
			
			unsigned char* point_ri = new unsigned char[crypto_core_ristretto255_BYTES];
			ristretto_ropoField2Group(mG_pairs_subsetsum[idx].second, point_ri,mfe25519_one);
			std::cout << "r point_ri= " << toBlock((u8*)point_ri) << "\n";
#endif // DEBUG_MINI_PSI_RIS
#else
			ZZFromBytes(zz, mG_pairs[idx], mPolyBytes);

#ifdef DEBUG_MINI_PSI_RIS
			std::cout << idx << " r P(x)= " << toBlock((u8*)mG_pairs[idx])
				<< " - " << toBlock(mG_pairs[idx] + sizeof(block)) << std::endl;

			unsigned char* point_ri = new unsigned char[crypto_core_ristretto255_BYTES];
			ristretto_ropoField2Group(mG_pairs[idx], point_ri, mfe25519_one);
			std::cout << "r point_ri= " << toBlock((u8*)point_ri) << "\n";
#endif // DEBUG_MINI_PSI_RIS
#endif

			zzY[idx] = to_ZZ_p(zz);
		}


		prepareForInterpolate(zzX, degree, M, a, numThreads, mPrime);


		iterative_interpolate_zp(Polynomial, temp, zzY, a, M, degree * 2 + 1, numThreads, mPrime);

		u64 iterSends = 0;
		sendBuff.resize(inputs.size() * mPolyBytes);
		for (int c = 0; c <= degree; c++) {
			BytesFromZZ(sendBuff.data() + iterSends, rep(Polynomial.rep[c]), mPolyBytes);

#ifdef DEBUG_MINI_PSI_RIS
			std::cout << "r SetCoeff rcvBlk= " << c << " - " 
				<< toBlock(sendBuff.data() + iterSends) << "\t"
			<< toBlock(sendBuff.data() + iterSends+sizeof(block)) << std::endl;
#endif // DEBUG_MINI_PSI_RIS

			iterSends += mPolyBytes;

		}

		chls[0].asyncSend(std::move(sendBuff));

		gTimer.setTimePoint("r Poly done");
		std::cout << "r Poly done\n";



		//#####################(g^K)^ (subsum ri) #####################
		//compute seeds (g^K)^ri
		//generate all pairs from seeds
		std::unordered_map<u64, std::pair<block, u64>> localMasks;
		localMasks.reserve(inputs.size());

#ifdef MINI_PSI_Subsetsum
		std::vector<unsigned char*> pgK_seeds(mSetSeedsSize);

		//seeds
		for (u64 i = 0; i < mSetSeedsSize; i++)
		{
			//compute (g^k)^ri
			pgK_seeds[i] = new unsigned char[crypto_core_ristretto255_BYTES];

			if (crypto_scalarmult_ristretto255(pgK_seeds[i], nSeeds[i], g_k) != 0) {

				std::cout << "crypto_scalarmult_ristretto255(pgK_seeds[i], nSeeds[i], g_k) != 0\n";
				throw std::runtime_error("rt error at " LOCATION);
			}
		}

		gTimer.setTimePoint("r g^k^seed done");

		for (u64 i = 0; i < inputs.size(); i++)
		{
			unsigned char gk_sum[crypto_core_ristretto255_BYTES]{};
			int j = 0;

			if (mBoundCoeffs == 2)
			{	//for (u64 j = 0; j < mG_pairs_subsetsum[i].first.size(); j++) //for all subset ri
				for (auto it = mG_pairs_subsetsum[i].first.begin(); it != mG_pairs_subsetsum[i].first.end(); ++it) //for all subset ri
					crypto_core_ristretto255_add(gk_sum, gk_sum, pgK_seeds[*it]); //(g^k)^(subsum ri)
			}
			else
			{
				std::cout << "mBoundCoeffs Don't support\n";
				throw std::runtime_error("rt error at " LOCATION);

				////for (u64 j = 0; j < mG_pairs_subsetsum[i].first.size(); j++) //for all subset ri
				//for (auto it = mG_pairs_subsetsum[i].first.begin(); it != mG_pairs_subsetsum[i].first.end(); ++it) //for all subset ri
				//{
				//	EccNumber ci(mCurve, mIntCi[i][j]);
				//	//tempCurve.fromBytes(mgK_seeds_bytes[mG_pairs_subsetsum[i].first[j]]);
				//	gk_sum = gk_sum + pgK_seeds[*it] * ci; //(g^k)^(subsum ri)
				//	j++;
				//}
			}

#ifdef DEBUG_MINI_PSI_RIS
			std::cout << "r (g^ri)^k= " << toBlock((u8*)&gk_sum) << "\n";
			std::cout << "r (g^ri)^k= " << toBlock((u8*)gk_sum) << "\n";
#endif // DEBUG_MINI_PSI_RIS

			block temp = toBlock((u8*)&gk_sum);
			localMasks.emplace(*(u64*)&temp, std::pair<block, u64>(temp, i));
		}
		//std::cout << "r g^k^ri done\n";
#else
		unsigned char gk_sum[crypto_core_ristretto255_BYTES]{};

		for (u64 i = 0; i < inputs.size(); i++)
		{
			//compute (g^k)^ri

			if (crypto_scalarmult_ristretto255(gk_sum, mScalars[i], g_k) != 0) {

				std::cout << "crypto_scalarmult_ristretto255(gk_sum, mScalars[i], g_k) != 0) != 0\n";
				throw std::runtime_error("rt error at " LOCATION);
			}

			block temp = toBlock((u8*)&gk_sum);
			localMasks.emplace(*(u64*)&temp, std::pair<block, u64>(temp, i));
		}

#endif

		gTimer.setTimePoint("r g^k^ri done");

		//#####################Receive Mask #####################


		auto receiveMask = [&](u64 t)
		{
			auto& chl = chls[t]; //parallel along with inputs
			u64 startIdx = mTheirInputSize * t / numThreads;
			u64 tempEndIdx = mTheirInputSize* (t + 1) / numThreads;
			u64 endIdx = std::min(tempEndIdx, mTheirInputSize);

			//std::cout << startIdx << " vs  " << endIdx << " rrrendIdx \n";

			for (u64 i = startIdx; i < endIdx; i += stepSizeMaskSent)
			{
				auto curStepSize = std::min(stepSizeMaskSent, endIdx - i);
				std::vector<u8> recvBuffs;

				chl.recv(recvBuffs); //receive Hash


				auto theirMasks = recvBuffs.data();
				//std::cout << "r toBlock(recvBuffs): " << i << " - " << toBlock(theirMasks) << std::endl;


				if (n1n2MaskBytes >= sizeof(u64)) //unordered_map only work for key >= 64 bits. i.e. setsize >=2^12
				{
					for (u64 k = 0; k < curStepSize; ++k)
					{

						auto& msk = *(u64*)(theirMasks);

						//std::cout << "r msk: " << i+k << " - " << toBlock(msk) << std::endl;

						// check 64 first bits
						auto match = localMasks.find(msk);

						//if match, check for whole bits
						if (match != localMasks.end())
						{
							//std::cout << "match != localMasks.end()" << std::endl;

							if (memcmp(theirMasks, &match->second.first, n1n2MaskBytes) == 0) // check full mask
							{
								if (isMultiThreaded)
								{
									std::lock_guard<std::mutex> lock(mtx);
									mIntersection.push_back(match->second.second);
								}
								else
								{
									mIntersection.push_back(match->second.second);
								}
							}
						}
						theirMasks += n1n2MaskBytes;
					}
				}
				else //for small set, do O(n^2) check
				{
					for (u64 k = 0; k < curStepSize; ++k)
					{
						//std::cout << "r theirMasks: " << i + k << " - " << toBlock(theirMasks) << std::endl;
						for (auto match = localMasks.begin(); match != localMasks.end(); ++match)
						{
							//std::cout << "r myMasks: " << i + k << " - " << match->second.first << std::endl;

							if (memcmp(theirMasks, &match->second.first, n1n2MaskBytes) == 0) // check full mask
								if (isMultiThreaded)
								{
									std::lock_guard<std::mutex> lock(mtx);
									mIntersection.push_back(match->second.second);
								}
								else
								{
									mIntersection.push_back(match->second.second);
								}
						}
						theirMasks += n1n2MaskBytes;

					}
				}

			}

		};

		for (u64 i = 0; i < thrds.size(); ++i)//thrds.size()
		{
			thrds[i] = std::thread([=] {
				receiveMask(i);
			});
		}

		for (auto& thrd : thrds)
			thrd.join();
#endif
		gTimer.setTimePoint("r on masks done");
		std::cout << "psi done\n";

	}


	void MiniReceiver_Ris::outputBigPoly_elligator(u64 myInputSize, u64 theirInputSize, u64 psiSecParam, PRNG& prng, span<block> inputs, span<Channel> chls)
	{
		using Block = typename Rijndael256Enc::Block;
		const std::uint8_t userKeyArr[] = {
			0x6e, 0x49, 0x0e, 0xe6, 0x2b, 0xa8, 0xf4, 0x0a,
			0x95, 0x83, 0xff, 0xa1, 0x59, 0xa5, 0x9d, 0x33,
			0x1d, 0xa6, 0x15, 0xcd, 0x1e, 0x8c, 0x75, 0xe1,
			0xea, 0xe3, 0x35, 0xe4, 0x76, 0xed, 0xf1, 0xdf,
		};
		Block userKey = Block256(userKeyArr);
		Rijndael256Enc encKey(userKey);

		for (u64 i = 0; i < chls.size(); ++i)
		{
			u8 dummy[1];
			chls[i].asyncSend(dummy, 1);
			chls[i].recv(dummy, 1);
			chls[i].resetStats();
		}
		gTimer.reset();
		//####################### offline #########################
		gTimer.setTimePoint("r offline start ");

		ropo_fe25519_1(mfe25519_one);
		mPsiSecParam = psiSecParam;
		mMyInputSize = myInputSize;
		mTheirInputSize = theirInputSize;
		mPrng.SetSeed(prng.get<block>());

		//2*number of group needded for T^-1
		getBestExpParams(2 * mMyInputSize, mSetSeedsSize, mChoseSeedsSize, mBoundCoeffs);

		std::cout << "r mSetSeedsSize= " << mMyInputSize << " - " << mSetSeedsSize << " - " << mChoseSeedsSize << "\n";

		mFieldSize = crypto_core_ristretto255_BYTES;
		mPolyBytes = mFieldSize;
		mCurveByteSize = mFieldSize;

#ifdef MINI_PSI_Subsetsum
		std::cout << "MINI_PSI_Subsetsum: Yes \n";
		std::vector<unsigned char*> nSeeds(mSetSeedsSize); //number
		std::vector<unsigned char*> pG_seeds(mSetSeedsSize); //g^num


			//seeds
		for (u64 i = 0; i < mSetSeedsSize; i++)
		{
			// get a random value from Z_p
			nSeeds[i] = new unsigned char[crypto_core_ristretto255_SCALARBYTES];
			crypto_core_ristretto255_scalar_random(nSeeds[i]);

			//      pG_seeds[i] = g ^ mSeeds[i]
			pG_seeds[i] = new unsigned char[crypto_core_ristretto255_BYTES];;  //g^ri
			crypto_scalarmult_ristretto255_base(pG_seeds[i], nSeeds[i]);
			//std::cout << mG_seeds[i] << std::endl;
		}
		std::cout << "pG_seeds done" << std::endl;
		gTimer.setTimePoint("r off pG_seeds done");

		//generate all pairs from seeds
		std::vector<std::pair<std::set<u64>, unsigned char*>> mG_pairs_subsetsum; //{index of sub ri}, g^(subsum ri)
		mG_pairs_subsetsum.reserve(myInputSize);

		std::set<u64> indices;

		mIntCi.resize(mMyInputSize);

		for (u64 i = 0; i < myInputSize; i++)
		{

			std::vector<unsigned char*> buffs;

			unsigned char g_sum[crypto_core_ristretto255_BYTES] = {};

			do {

				indices.clear();
				while (indices.size() < mChoseSeedsSize)
					indices.insert(rand() % mSetSeedsSize);


				/*ri[i] = 0;
				for (u64 j = 0; j < mChoseSeedsSize; j++)
					ri[i] = ri[i] + nSeeds[indices[j]];*/

				if (mBoundCoeffs == 2) //most cases
				{
					//for (u64 j = 0; j < mChoseSeedsSize; j++)
					for (auto it = indices.begin(); it != indices.end(); ++it)
						crypto_core_ristretto255_add(g_sum, g_sum, pG_seeds[*it]); //g^sum //h=2   ci=1
				}
				else
				{
					std::cout << "mBoundCoeffs Don't support\n";
					throw std::runtime_error("rt error at " LOCATION);
					//mIntCi[i].resize(mChoseSeedsSize);

					//int j = 0;
					//for (auto it = indices.begin(); it != indices.end(); ++it)
					//{
					//	mIntCi[i][j] = 1 + rand() % (mBoundCoeffs - 1);

					//	EccNumber ci(mCurve, mIntCi[i][j]);
					//	g_sum = g_sum + pG_seeds[*it] * ci; //g^ci*sum
					//	j++;
					//}
				}
				//g_sum = mG * ri[i];


				buffs.clear();
				ristretto_ropoGroup2Field(g_sum, buffs, mfe25519_one);
			} while (buffs.size() == 0);

#ifdef DEBUG_MINI_PSI_RIS
			std::cout << toBlock((u8*)&g_sum) << "\t r orignial point#######\n";
#endif // DEBUG_MINI_PSI_RIS

			int rand_idx = rand() % buffs.size(); //choose random si
			mG_pairs_subsetsum.push_back(std::make_pair(indices, buffs[rand_idx]));

			/*unsigned char* point_ri = new unsigned char[crypto_core_ristretto255_BYTES];
			ristretto_ropoField2Group(buffs[rand_idx], point_ri, mfe25519_one);
			std::cout << "rrr point_ri= " << toBlock((u8*)point_ri) << "\n";*/
		}
#else
		mScalars.resize(myInputSize);

		unsigned char pk[crypto_core_ristretto255_BYTES] = {};
		unsigned char representative[crypto_core_ristretto255_BYTES] = {};
		bool success;
		mG_pairs_elligator.resize(first2Slices);

		for (u64 i = 0; i < myInputSize; i++)
		{

			std::vector<unsigned char*> buffs;

			mScalars[i] = new unsigned char[crypto_core_ristretto255_SCALARBYTES];

			do {
				buffs.clear();

				crypto_core_ristretto255_scalar_random(mScalars[i]);
				success = ScalarBaseMult2(pk, representative, mScalars[i]);
				//ristretto_ropoGroup2Field(g_sum, buffs, mfe25519_one);
			} while (!success);

			auto permute_ctxt = encKey.encBlock(Block256(representative));
			mG_pairs_elligator[0].push_back(toBlock(permute_ctxt.data()));
			mG_pairs_elligator[1].push_back(toBlock(permute_ctxt.data()+ sizeof(block)));


#ifdef DEBUG_MINI_PSI_RIS
			std::cout << "rrr representative= " << toBlock(representative) << "\n";
			std::cout << "rrr representative2= " << toBlock(representative + sizeof(block)) << "\n";
			//std::cout << "rrr representative= " << toBlock((u8*)&representative) << "\n";

			std::cout << toBlock((u8*)&g_sum) << "\t r orignial point#######\n";
			unsigned char* point_ri = new unsigned char[crypto_core_ristretto255_BYTES];
			ristretto_ropoField2Group(buffs[rand_idx], point_ri, mfe25519_one);
			std::cout << "rrr point_ri= " << toBlock((u8*)point_ri) << "\n";
#endif // DEBUG_MINI_PSI_RIS

		}
#endif

		std::cout << "r mG_pairs_elligator done" << std::endl;

		//####################### online #########################
		gTimer.setTimePoint("r online start ");

		unsigned char g_k[crypto_core_ristretto255_BYTES];
		chls[0].recv(g_k); //receiving g^k
		//std::cout << "r g^k= " << toBlock((u8*)&g_k) << std::endl;


		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;
		std::vector<std::thread> thrds(numThreads);
		std::mutex mtx;

		u64 n1n2MaskBits = 2*128; //(40 + log2(mTheirInputSize * mMyInputSize));
		u64 n1n2MaskBytes = (n1n2MaskBits + 7) / 8;
		//std::cout << n1n2MaskBytes << " r n1n2MaskBytes\n";



#if 1
		//#####################Poly#####################
		//slicing
		mPrime = mPrime128;
		ZZ_p::init(ZZ(mPrime));

		u64 degree = inputs.size() - 1;
		ZZ_p* zzX = new ZZ_p[inputs.size()];

		std::array<ZZ_p*, first2Slices> zzY;
		for (u64 i = 0; i < first2Slices; i++)
			zzY[i] = new ZZ_p[inputs.size()];


		ZZ zz;
		ZZ_pX* M = new ZZ_pX[degree * 2 + 1];;
		ZZ_p* a = new ZZ_p[degree + 1];;
		ZZ_pX* temp = new ZZ_pX[degree * 2 + 1];

		std::array<ZZ_pX, first2Slices> Polynomials;
		std::array<std::vector<u8>, first2Slices> sendBuffs;


		for (u64 idx = 0; idx < inputs.size(); idx++)
		{
			ZZFromBytes(zz, (u8*)&inputs[idx], sizeof(block));
			zzX[idx] = to_ZZ_p(zz);
		}

		for (u64 idx = 0; idx < inputs.size(); idx++)
		{
			for (u64 idxBlk = 0; idxBlk < first2Slices; idxBlk++)
			{
				//u8* yri = new u8[mPolyBytes];

#ifdef MINI_PSI_Subsetsum

				ZZFromBytes(zz, mG_pairs_subsetsum[idx].second, mPolyBytes);

#ifdef DEBUG_MINI_PSI_RIS
				std::cout << idx << " r P(x)= " << toBlock((u8*)mG_pairs_subsetsum[idx].second)
					<< " - " << toBlock(mG_pairs_subsetsum[idx].second + sizeof(block)) << std::endl;

				unsigned char* point_ri = new unsigned char[crypto_core_ristretto255_BYTES];
				ristretto_ropoField2Group(mG_pairs_subsetsum[idx].second, point_ri, mfe25519_one);
				std::cout << "r point_ri= " << toBlock((u8*)point_ri) << "\n";
#endif // DEBUG_MINI_PSI_RIS
#else
				ZZFromBytes(zz, (u8*)&mG_pairs_elligator[idxBlk][idx], std::min(sizeof(block),mPolyBytes- sizeof(block)));


#ifdef DEBUG_MINI_PSI_RIS
				std::cout << idx << " r P(x)= " << toBlock((u8*)mG_pairs[idx])
					<< " - " << toBlock(mG_pairs[idx] + sizeof(block)) << std::endl;

				unsigned char* point_ri = new unsigned char[crypto_core_ristretto255_BYTES];
				ristretto_ropoField2Group(mG_pairs[idx], point_ri, mfe25519_one);
				std::cout << "r point_ri= " << toBlock((u8*)point_ri) << "\n";
#endif // DEBUG_MINI_PSI_RIS
#endif

				zzY[idxBlk][idx] = to_ZZ_p(zz);
			}
		}


		prepareForInterpolate(zzX, degree, M, a, numThreads, mPrime);

		for (u64 idxBlk = 0; idxBlk < first2Slices; idxBlk++)
		{
			iterative_interpolate_zp(Polynomials[idxBlk], temp, zzY[idxBlk], a, M, degree * 2 + 1, numThreads, mPrime);

			u64 subPolyBytesize = std::min(sizeof(block), mPolyBytes - sizeof(block));

			u64 iterSends = 0;
			sendBuffs[idxBlk].resize(inputs.size() * subPolyBytesize);
			for (int c = 0; c <= degree; c++) {
				BytesFromZZ(sendBuffs[idxBlk].data() + iterSends, rep(Polynomials[idxBlk].rep[c]), subPolyBytesize);


#ifdef DEBUG_MINI_PSI_RIS
				std::cout << "r SetCoeff rcvBlk= " << c << " - " << toBlock(sendBuffs[idxBlk].data() + iterSends) << std::endl;
#endif // DEBUG_MINI_PSI_RIS

				iterSends += subPolyBytesize;
			}
			chls[0].asyncSend(std::move(sendBuffs[idxBlk]));

		}


		gTimer.setTimePoint("r Poly done");
		std::cout << "r Poly done\n";



		//#####################(g^K)^ (subsum ri) #####################
		//compute seeds (g^K)^ri
		//generate all pairs from seeds
		std::unordered_map<u64, std::pair<block, u64>> localMasks;
		localMasks.reserve(inputs.size());

#ifdef MINI_PSI_Subsetsum
		std::vector<unsigned char*> pgK_seeds(mSetSeedsSize);

		//seeds
		for (u64 i = 0; i < mSetSeedsSize; i++)
		{
			//compute (g^k)^ri
			pgK_seeds[i] = new unsigned char[crypto_core_ristretto255_BYTES];

			if (crypto_scalarmult_ristretto255(pgK_seeds[i], nSeeds[i], g_k) != 0) {

				std::cout << "crypto_scalarmult_ristretto255(pgK_seeds[i], nSeeds[i], g_k) != 0\n";
				throw std::runtime_error("rt error at " LOCATION);
			}
		}

		gTimer.setTimePoint("r g^k^seed done");

		for (u64 i = 0; i < inputs.size(); i++)
		{
			unsigned char gk_sum[crypto_core_ristretto255_BYTES]{};
			int j = 0;

			if (mBoundCoeffs == 2)
			{	//for (u64 j = 0; j < mG_pairs_subsetsum[i].first.size(); j++) //for all subset ri
				for (auto it = mG_pairs_subsetsum[i].first.begin(); it != mG_pairs_subsetsum[i].first.end(); ++it) //for all subset ri
					crypto_core_ristretto255_add(gk_sum, gk_sum, pgK_seeds[*it]); //(g^k)^(subsum ri)
			}
			else
			{
				std::cout << "mBoundCoeffs Don't support\n";
				throw std::runtime_error("rt error at " LOCATION);

				////for (u64 j = 0; j < mG_pairs_subsetsum[i].first.size(); j++) //for all subset ri
				//for (auto it = mG_pairs_subsetsum[i].first.begin(); it != mG_pairs_subsetsum[i].first.end(); ++it) //for all subset ri
				//{
				//	EccNumber ci(mCurve, mIntCi[i][j]);
				//	//tempCurve.fromBytes(mgK_seeds_bytes[mG_pairs_subsetsum[i].first[j]]);
				//	gk_sum = gk_sum + pgK_seeds[*it] * ci; //(g^k)^(subsum ri)
				//	j++;
				//}
			}

#ifdef DEBUG_MINI_PSI_RIS
			std::cout << "r (g^ri)^k= " << toBlock((u8*)&gk_sum) << "\n";
			std::cout << "r (g^ri)^k= " << toBlock((u8*)gk_sum) << "\n";
#endif // DEBUG_MINI_PSI_RIS

			block temp = toBlock((u8*)&gk_sum);
			localMasks.emplace(*(u64*)&temp, std::pair<block, u64>(temp, i));
		}
		//std::cout << "r g^k^ri done\n";
#else
		unsigned char gk_sum[crypto_core_ristretto255_BYTES]{};

		for (u64 i = 0; i < inputs.size(); i++)
		{
			//compute (g^k)^ri

			if (crypto_scalarmult_ristretto255(gk_sum, mScalars[i], g_k) != 0) {

				std::cout << "crypto_scalarmult_ristretto255(gk_sum, mScalars[i], g_k) != 0) != 0\n";
				throw std::runtime_error("rt error at " LOCATION);
			}

			block temp = toBlock((u8*)&gk_sum);
			localMasks.emplace(*(u64*)&temp, std::pair<block, u64>(temp, i));
		}

#endif

		gTimer.setTimePoint("r g^k^ri done");

		//#####################Receive Mask #####################


		auto receiveMask = [&](u64 t)
		{
			auto& chl = chls[t]; //parallel along with inputs
			u64 startIdx = mTheirInputSize * t / numThreads;
			u64 tempEndIdx = mTheirInputSize * (t + 1) / numThreads;
			u64 endIdx = std::min(tempEndIdx, mTheirInputSize);

			//std::cout << startIdx << " vs  " << endIdx << " rrrendIdx \n";

			for (u64 i = startIdx; i < endIdx; i += stepSizeMaskSent)
			{
				auto curStepSize = std::min(stepSizeMaskSent, endIdx - i);
				std::vector<u8> recvBuffs;

				chl.recv(recvBuffs); //receive Hash


				auto theirMasks = recvBuffs.data();
				//std::cout << "r toBlock(recvBuffs): " << i << " - " << toBlock(theirMasks) << std::endl;


				if (n1n2MaskBytes >= sizeof(u64)) //unordered_map only work for key >= 64 bits. i.e. setsize >=2^12
				{
					for (u64 k = 0; k < curStepSize; ++k)
					{

						auto& msk = *(u64*)(theirMasks);

						//std::cout << "r msk: " << i+k << " - " << toBlock(msk) << std::endl;

						// check 64 first bits
						auto match = localMasks.find(msk);

						//if match, check for whole bits
						if (match != localMasks.end())
						{
							//std::cout << "match != localMasks.end()" << std::endl;

							if (memcmp(theirMasks, &match->second.first, n1n2MaskBytes) == 0) // check full mask
							{
								if (isMultiThreaded)
								{
									std::lock_guard<std::mutex> lock(mtx);
									mIntersection.push_back(match->second.second);
								}
								else
								{
									mIntersection.push_back(match->second.second);
								}
							}
						}
						theirMasks += n1n2MaskBytes;
					}
				}
				else //for small set, do O(n^2) check
				{
					for (u64 k = 0; k < curStepSize; ++k)
					{
						//std::cout << "r theirMasks: " << i + k << " - " << toBlock(theirMasks) << std::endl;
						for (auto match = localMasks.begin(); match != localMasks.end(); ++match)
						{
							//std::cout << "r myMasks: " << i + k << " - " << match->second.first << std::endl;

							if (memcmp(theirMasks, &match->second.first, n1n2MaskBytes) == 0) // check full mask
								if (isMultiThreaded)
								{
									std::lock_guard<std::mutex> lock(mtx);
									mIntersection.push_back(match->second.second);
								}
								else
								{
									mIntersection.push_back(match->second.second);
								}
						}
						theirMasks += n1n2MaskBytes;

					}
				}

			}

		};

		for (u64 i = 0; i < thrds.size(); ++i)//thrds.size()
		{
			thrds[i] = std::thread([=] {
				receiveMask(i);
				});
		}

		for (auto& thrd : thrds)
			thrd.join();
#endif
		gTimer.setTimePoint("r on masks done");
		std::cout << "psi done\n";

	}


}
