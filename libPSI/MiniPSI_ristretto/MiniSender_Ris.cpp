#include "MiniSender_Ris.h"

#include <cryptoTools/Crypto/Commit.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Common/Timer.h>
#include <unordered_map>
#include <cryptoTools/Crypto/Rijndael256.h>

namespace osuCrypto
{
    using namespace std;
	using namespace NTL;




	void MiniSender_Ris::outputBigPoly(u64 myInputSize, u64 theirInputSize, u64 psiSecParam, PRNG & prng, span<block> inputs, span<Channel> chls)
	{
		for (u64 i = 0; i < chls.size(); ++i)
		{
			u8 dummy[1];
			chls[i].recv(dummy, 1);
			chls[i].asyncSend(dummy, 1);
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
		mCurveSeed = mPrng.get<block>();
	
		simple.init(mTheirInputSize, recvMaxBinSize, recvNumDummies);

		mFieldSize = crypto_core_ristretto255_BYTES;
		mPolyBytes = mFieldSize;

		//std::cout << "s mFieldSize= " << mFieldSize << "\n";


		mK = new unsigned char[crypto_core_ristretto255_SCALARBYTES];
		mG_K = new unsigned char[crypto_core_ristretto255_BYTES];
		crypto_core_ristretto255_scalar_random(mK);
		crypto_scalarmult_ristretto255_base(mG_K, mK); //g^k

		//std::cout << "s k= " << toBlock((u8*)mK) << std::endl;
		//std::cout << "s g^k= " << toBlock((u8*)mG_K) << std::endl;

		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;
		std::vector<std::thread> thrds(numThreads);
		std::mutex mtx;


		u64 n1n2MaskBits = 2*128;//(40 + log2(mTheirInputSize*mMyInputSize));
		u64 n1n2MaskBytes = (n1n2MaskBits + 7) / 8;
		std::vector<u8> tempSend(crypto_core_ristretto255_BYTES);
		memcpy(tempSend.data(), mG_K, crypto_core_ristretto255_BYTES);

		//####################### online #########################
		gTimer.setTimePoint("r online start ");
		chls[0].asyncSend(std::move(tempSend));//send g^k

#if 1

		//=====================Poly=====================
		u64 degree = mTheirInputSize - 1;
		
			int numEvalPoint = std::max(mMyInputSize, mTheirInputSize);//since the multipoint evalution require |X|>= |degree| => paadding (TODO: optimze it!)

			mPrime = myPrime;
			ZZ_p::init(ZZ(mPrime));

			ZZ_p* zzX = new ZZ_p[numEvalPoint]; 
			ZZ_p* zzY = new ZZ_p[numEvalPoint];
			ZZ zz;

			for (u64 idx = 0; idx < mMyInputSize; idx++)
			{
				ZZFromBytes(zz, (u8*)&inputs[idx], sizeof(block));
				zzX[idx] = to_ZZ_p(zz);
			}

			for (u64 idx = mMyInputSize; idx < numEvalPoint; idx++)
			{
				zzX[idx] = random_ZZ_p();
			}



			ZZ_pX* p_tree = new ZZ_pX[degree * 2 + 1];
			ZZ_pX* reminders = new ZZ_pX[degree * 2 + 1];
			

			build_tree(p_tree, zzX, degree * 2 + 1, numThreads, mPrime);
			u8* rcvBlk=new u8[mPolyBytes];

			ZZ_pX recvPolynomial;

			std::vector<u8> recvBuffs;

			
				u64 iterRecvs = 0;
				chls[0].recv(recvBuffs);
			
			gTimer.setTimePoint("s received coeff start ");


				//std::cout << "s recvBuffs[idxBlk].size(): " << recvBuffs.size() << std::endl;

				for (int c = 0; c <= degree; c++) {
					memcpy(rcvBlk, recvBuffs.data() + iterRecvs, mPolyBytes);
					iterRecvs += mPolyBytes;

#ifdef DEBUG_MINI_PSI_RIS
					std::cout << "s SetCoeff rcvBlk= " <<c << " - " << toBlock(rcvBlk) << "\t"
					<< toBlock(rcvBlk + sizeof(block)) << std::endl;
#endif // DEBUG_MINI_PSI_RIS

					ZZFromBytes(zz, rcvBlk, mPolyBytes);
					SetCoeff(recvPolynomial, c, to_ZZ_p(zz));
				}
				evaluate(recvPolynomial, p_tree, reminders, degree * 2 + 1, zzY, numThreads, mPrime);

#ifdef DEBUG_MINI_PSI_RIS

			for (u64 idx = 0; idx < inputs.size(); idx++)
				{
					u8* pY=new u8[mPolyBytes];
					BytesFromZZ(pY, rep(zzY[idx]), mPolyBytes);
					std::cout << "s P(y)= " << idx << " - " << toBlock(pY) 
						<< " - " << toBlock(pY + sizeof(block)) << std::endl;
				}
#endif // DEBUG_MINI_PSI_RIS

				std::cout << "s Poly done\n";
				gTimer.setTimePoint("s Poly done");

		auto computeGlobalHash = [&](u64 t)
		{
			u64 startIdx = mMyInputSize * t / numThreads;
			u64 tempEndIdx = mMyInputSize* (t + 1) / numThreads;
			u64 endIdx = std::min(tempEndIdx, mMyInputSize);

			//std::cout << startIdx << " vs  " << endIdx << " sssendIdx \n";

			for (u64 i = startIdx; i < endIdx; i += stepSizeMaskSent)
			{
				auto curStepSize = std::min(stepSizeMaskSent, endIdx - i);

				std::vector<u8> sendBuff(n1n2MaskBytes * curStepSize);

				//std::cout << "s startIdx= " << startIdx << "s endIdx= " << endIdx << std::endl;

				unsigned char* point_ri = new unsigned char[crypto_core_ristretto255_BYTES];

				for (u64 idx = 0; idx < curStepSize; idx++) 
				{
					//std::cout << "s idx= " << idx << std::endl;
					u64 idxItem = i + idx;

					BytesFromZZ(point_ri, rep(zzY[idxItem]), mPolyBytes);

					//if(mPolyBytes!= point_ri.sizeBytes())
					//	std::cout << "mPolyBytes!= point_ri.sizeBytes()" << mPolyBytes <<" != "<< point_ri.sizeBytes() << std::endl;

					//std::cout <<idx << " s yri= " << toBlock(yri) <<" - " << toBlock(yri+ sizeof(block)) << std::endl;


					ristretto_ropoField2Group(point_ri, point_ri, mfe25519_one);



					//std::cout  << point_ri << std::endl;

					unsigned char* yri_K=new unsigned char[crypto_core_ristretto255_BYTES];

					//(g^ri)^k
					crypto_scalarmult_ristretto255(yri_K, mK, point_ri);
					
					//SHA2
					//std::cout <<idx << "s yri_K= " << yri_K << std::endl;

					memcpy(sendBuff.data() + idx*n1n2MaskBytes, yri_K, n1n2MaskBytes);

#ifdef DEBUG_MINI_PSI_RIS
					std::cout << "s point_ri= " << toBlock((u8*)point_ri) << "\n";
					std::cout << "s (g^ri)^k= " << toBlock((u8*)yri_K) << "\n";
#endif // DEBUG_MINI_PSI_RIS

					//std::cout << "s sendIter= " << idxItem << " - " << toBlock(temp) << std::endl;
				}

				//std::cout << "s toBlock(sendBuff): "<< toBlock(sendBuff.data()) << std::endl;

				chls[t].asyncSend(std::move(sendBuff));	// some bits of g^(subsum ri)^k
			}
		};


		for (u64 i = 0; i < thrds.size(); ++i)
		{
			thrds[i] = std::thread([=] {
				computeGlobalHash(i);
			});
		}
		for (auto& thrd : thrds)
			thrd.join();

		std::cout << "s mask done\n";
#endif
		gTimer.setTimePoint("s mask done");

	}



	void MiniSender_Ris::outputBigPoly_elligator(u64 myInputSize, u64 theirInputSize, u64 psiSecParam, PRNG& prng, span<block> inputs, span<Channel> chls)
	{
                using Block = typename Rijndael256Enc::Block;
		const std::uint8_t userKeyArr[] = {
			0x6e, 0x49, 0x0e, 0xe6, 0x2b, 0xa8, 0xf4, 0x0a,
			0x95, 0x83, 0xff, 0xa1, 0x59, 0xa5, 0x9d, 0x33,
			0x1d, 0xa6, 0x15, 0xcd, 0x1e, 0x8c, 0x75, 0xe1,
			0xea, 0xe3, 0x35, 0xe4, 0x76, 0xed, 0xf1, 0xdf,
		};
		Block userKey = Block256(userKeyArr);
		Rijndael256Dec decKey(userKey);

		for (u64 i = 0; i < chls.size(); ++i)
		{
			u8 dummy[1];
			chls[i].recv(dummy, 1);
			chls[i].asyncSend(dummy, 1);
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
		mCurveSeed = mPrng.get<block>();

		simple.init(mTheirInputSize, recvMaxBinSize, recvNumDummies);

		mFieldSize = crypto_core_ristretto255_BYTES;
		mPolyBytes = mFieldSize;

		//std::cout << "s mFieldSize= " << mFieldSize << "\n";


		mK = new unsigned char[crypto_core_ristretto255_SCALARBYTES];
		mG_K = new unsigned char[crypto_core_ristretto255_BYTES];
		crypto_core_ristretto255_scalar_random(mK);
		crypto_scalarmult_ristretto255_base(mG_K, mK); //g^k

		//std::cout << "s k= " << toBlock((u8*)mK) << std::endl;
		//std::cout << "s g^k= " << toBlock((u8*)mG_K) << std::endl;

		u64 numThreads(chls.size());
		const bool isMultiThreaded = numThreads > 1;
		std::vector<std::thread> thrds(numThreads);
		std::mutex mtx;


		u64 n1n2MaskBits = 2*128;// (40 + log2(mTheirInputSize * mMyInputSize));
		u64 n1n2MaskBytes = (n1n2MaskBits + 7) / 8;
		//std::cout << n1n2MaskBytes << " s n1n2MaskBytes\n";
		std::vector<u8> tempSend(crypto_core_ristretto255_BYTES);
		memcpy(tempSend.data(), mG_K, crypto_core_ristretto255_BYTES);

		//####################### online #########################
		gTimer.setTimePoint("r online start ");
		chls[0].asyncSend(std::move(tempSend));//send g^k

#if 1

		//=====================Poly=====================
		u64 degree = mTheirInputSize - 1;

		int numEvalPoint = std::max(mMyInputSize, mTheirInputSize);//since the multipoint evalution require |X|>= |degree| => paadding (TODO: optimze it!)

		mPrime = mPrime128;
		ZZ_p::init(ZZ(mPrime));

		ZZ_p* zzX = new ZZ_p[numEvalPoint];

		std::array<ZZ_p*, first2Slices> zzY;
		for (u64 i = 0; i < first2Slices; i++)
			zzY[i] = new ZZ_p[inputs.size()];

		ZZ zz;

		for (u64 idx = 0; idx < mMyInputSize; idx++)
		{
			ZZFromBytes(zz, (u8*)&inputs[idx], sizeof(block));
			zzX[idx] = to_ZZ_p(zz);
		}

		for (u64 idx = mMyInputSize; idx < numEvalPoint; idx++)
		{
			zzX[idx] = random_ZZ_p();
		}



		ZZ_pX* p_tree = new ZZ_pX[degree * 2 + 1];
		ZZ_pX* reminders = new ZZ_pX[degree * 2 + 1];


		build_tree(p_tree, zzX, degree * 2 + 1, numThreads, mPrime);
		u8* rcvBlk = new u8[mPolyBytes];

		std::array<ZZ_pX, first2Slices> recvPolynomials;



		for (u64 idxBlk = 0; idxBlk < first2Slices; idxBlk++)
		{
			//std::cout << "s idxBlk idxBlk= " << idxBlk << "\n";

			std::vector<u8> recvBuffs;
			u64 subPolyBytesize = std::min(sizeof(block), mPolyBytes - sizeof(block));

			u64 iterRecvs = 0;
			chls[0].recv(recvBuffs);

			gTimer.setTimePoint("s received coeff start ");


			//std::cout << "s recvBuffs[idxBlk].size(): " << recvBuffs.size() << std::endl;

			for (int c = 0; c <= degree; c++) {
				memcpy(rcvBlk, recvBuffs.data() + iterRecvs, subPolyBytesize);
				iterRecvs += subPolyBytesize;


#ifdef DEBUG_MINI_PSI_RIS
				std::cout << "s SetCoeff rcvBlk= " << c << " - " << toBlock(rcvBlk) << std::endl;

#endif // DEBUG_MINI_PSI_RIS

				ZZFromBytes(zz, rcvBlk, subPolyBytesize);
				SetCoeff(recvPolynomials[idxBlk], c, to_ZZ_p(zz));
			}

			evaluate(recvPolynomials[idxBlk], p_tree, reminders, degree * 2 + 1, zzY[idxBlk], numThreads, mPrime);

		}
#ifdef DEBUG_MINI_PSI_RIS

		for (u64 idx = 0; idx < inputs.size(); idx++)
		{
			u8* pY = new u8[mPolyBytes];
			BytesFromZZ(pY, rep(zzY[idx]), mPolyBytes);
			std::cout << "s P(y)= " << idx << " - " << toBlock(pY)
				<< " - " << toBlock(pY + sizeof(block)) << std::endl;
		}
#endif // DEBUG_MINI_PSI_RIS

		std::cout << "s Poly done\n";
		gTimer.setTimePoint("s Poly done");

		auto computeGlobalHash = [&](u64 t)
		{
			u64 startIdx = mMyInputSize * t / numThreads;
			u64 tempEndIdx = mMyInputSize * (t + 1) / numThreads;
			u64 endIdx = std::min(tempEndIdx, mMyInputSize);

			//std::cout << startIdx << " vs  " << endIdx << " sssendIdx \n";

			for (u64 i = startIdx; i < endIdx; i += stepSizeMaskSent)
			{
				auto curStepSize = std::min(stepSizeMaskSent, endIdx - i);

				std::vector<u8> sendBuff(n1n2MaskBytes * curStepSize);

				//std::cout << "s startIdx= " << startIdx << "s endIdx= " << endIdx << std::endl;

				unsigned char* point_ri = new unsigned char[crypto_core_ristretto255_BYTES];

				for (u64 idx = 0; idx < curStepSize; idx++)
				{
					//std::cout << "s idx= " << idx << std::endl;
					u64 idxItem = i + idx;

					for (u64 idxBlk = 0; idxBlk < first2Slices; ++idxBlk) //slicing
					{
						BytesFromZZ(point_ri+ idxBlk*sizeof(block), rep(zzY[idxBlk][idxItem])
							, std::min(sizeof(block), mPolyBytes - sizeof(block)));
					}

					//if(mPolyBytes!= point_ri.sizeBytes())
					//	std::cout << "mPolyBytes!= point_ri.sizeBytes()" << mPolyBytes <<" != "<< point_ri.sizeBytes() << std::endl;

					//std::cout <<idx << " s yri= " << toBlock(yri) <<" - " << toBlock(yri+ sizeof(block)) << std::endl;


					//ristretto_ropoField2Group(point_ri, point_ri, mfe25519_one);

					auto permute_ri = decKey.decBlock(Block256(point_ri));					
					point_ri = permute_ri.data();

					RepresentativeToPublicKey2(point_ri, point_ri);

					//std::cout  << point_ri << std::endl;

					unsigned char* yri_K = new unsigned char[crypto_core_ristretto255_BYTES];

					//(g^ri)^k
					crypto_scalarmult_ristretto255(yri_K, mK, point_ri);

				/*	SHA2 inputHasher;  
					u8 hashOut[SHA2::HashSize];
					inputHasher.Reset();
					inputHasher.Update(yri_K);
					inputHasher.Update(inputs[idxItem]);
				    inputHasher.Final(yri_K);
					*/

					//std::cout <<idx << "s yri_K= " << yri_K << std::endl;

					memcpy(sendBuff.data() + idx * n1n2MaskBytes, yri_K, n1n2MaskBytes);

#ifdef DEBUG_MINI_PSI_RIS
					std::cout << "s point_ri= " << toBlock((u8*)point_ri) << "\n";
					std::cout << "s (g^ri)^k= " << toBlock((u8*)yri_K) << "\n";
#endif // DEBUG_MINI_PSI_RIS

					//std::cout << "s sendIter= " << idxItem << " - " << toBlock(temp) << std::endl;
				}

				//std::cout << "s toBlock(sendBuff): "<< toBlock(sendBuff.data()) << std::endl;

				chls[t].asyncSend(std::move(sendBuff));	// some bits of g^(subsum ri)^k
			}
		};


		for (u64 i = 0; i < thrds.size(); ++i)
		{
			thrds[i] = std::thread([=] {
				computeGlobalHash(i);
				});
		}
		for (auto& thrd : thrds)
			thrd.join();

		std::cout << "s mask done\n";
#endif
		gTimer.setTimePoint("s mask done");

	}






}

