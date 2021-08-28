#  Private Set Intersection for Small Sets
This is the implementation of our [CCS 2021](http://dl.acm.org/citation.cfm?id=2978381)  paper: **Compact and Malicious Private Set Intersection for Small Sets**[[ePrint](https://eprint.iacr.org/2021)]. 


## Installations
### Clone project
```
git clone --recursive git@github.com:osu-crypto/MiniPSI.git
```

### Quick Installation (Linux)
    $ cd MiniPSI
    $ bash buildAll.get

If you have any problem, see below.

### Required libraries
 C++ compiler with C++14 support. There are several library dependencies including [`Boost`](https://sourceforge.net/projects/boost/), [`Miracl`](https://github.com/miracl/MIRACL), [`NTL`](http://www.shoup.net/ntl/) with GMP, and [`libOTe`](https://github.com/osu-crypto/libOTe). For `libOTe`, it requires CPU supporting `PCLMUL`, `AES-NI`, and `SSE4.1`. Optional: `nasm` for improved SHA1 performance.   Our code has been tested on both Windows (Microsoft Visual Studio) and Linux. To install the required libraries: 
  * For building boost, miracl and libOTe, please follow the more instructions at [`libOTe`](https://github.com/osu-crypto/libOTe). A quick try for linux: `cd libOTe/cryptoTools/thirdparty/linux/`, `bash all.get`, `cd` back to `libOTe`, `cmake .` and then `make -j`
  * For NTL with GMP and gf2x, `cd ./thirdparty/linux`, and run `all.get`. Then, you can run `cmake .` in  SpOT-PSI folder, and then `make -j`  
  * See [`here`](https://github.com/osu-crypto/SpOT-PSI/blob/master/script/setup_and_compile) for full setup script 

NOTE: if you meet problem with NTL, try to do the following and read [`Building and using NTL with GMP`](https://www.shoup.net/ntl/doc/tour-gmp.html). If you see an error message `cmd.exe not found`, try to install https://www.nasm.us/

### Building the Project
After cloning project from git, 
##### Windows:
1. build cryptoTools,libOTe, libsodium, libPSI projects in order.
2. add argument for frontend project (for example: -t)
3. run frontend project
 
##### Linux:
1. make (requirements: `CMake`, `Make`, `g++` or similar)
2. for test:
	./bin/frontend.exe -t


## Running the code
The database is generated randomly. The outputs include the average online/offline/total runtime that displayed on the screen and output.txt. 
#### Flags:
   -t		unit test which computes PSI of 2 paries, each with set size 2^8 in semi-honest setting
   -n		log of receiver's set size (e.g. n=8 => setsize =2^8)
   -m		log of sender's set size (e.g. n=8 => setsize =2^8)
   -r           evaluating DH-based PSI
   -e	        evaluating JL10-based PSI
   -i           evaluating our poly-based protocol
   
#### Examples: 
##### 1. Unit test:
	./bin/frontend.exe -t
	
##### 2. PSI:
DH-based PSI

	./bin/frontend.exe -r 0 -n 10  & ./bin/frontend.exe -r 1 -n 10

	
JL10-based PSI

	./bin/frontend.exe -e 0 -n 10  & ./bin/frontend.exe -e 1 -n 10
 
our protocol (Poly-based PSI)

	./bin/frontend.exe -i 0 -n 10  & ./bin/frontend.exe -i 1 -n 10
 
		
## Help
For any questions on building or running the library, please contact [`Ni Trieu`](http://people.oregonstate.edu/~trieun/) at trieun at oregonstate dot edu

