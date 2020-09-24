$RemoteUserName='coe_nitrieu'
$RemoteHostName='eve.eecs.oregonstate.edu'
$PrivateKey='C:\Putty\EvePrivatekey.ppk'
$SolutionDir=$PWD
$RemoteWorkingDir='/scratch/ni_new/miniPSI'

# only files with these extensions will be copied
$FileMasks='**.cpp;**.c;**.h;*.bin,*.S,*.sh,*CMake*;*/Tools/*.txt;*/gsl/*;**.mak;thirdparty/linux/**.get;*/libOTe_Tests/testData/*.txt,*.get'

# everything in these folders will be skipped
$ExcludeDirs='.git/;thirdparty/;Debug/;Release/;x64/;ipch/;.vs/'

C:\WinSCP\WinSCP.com  /command `
    "open $RemoteUserName@$RemoteHostName -privatekey=""$PrivateKey"""`
    "call mkdir -p $RemoteWorkingDir"`
    "synchronize Remote $SolutionDir $RemoteWorkingDir -filemask=""$FileMasks|$ExcludeDirs;"" -transfer=binary"`
    "call mkdir -p $RemoteWorkingDir/cryptoTools/thirdparty/"`
    "call mkdir -p $RemoteWorkingDir/cryptoTools/thirdparty/linux/"`
    "synchronize remote $SolutionDir/cryptoTools/thirdparty/linux/ $RemoteWorkingDir/cryptoTools/thirdparty/linux/ -filemask=""**.get"" -transfer=binary"`
    "exit" 