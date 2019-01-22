
cd depends;
make download;make download-osx;make download-win;make download-linux;
make HOST=x86_64-pc-linux-gnu;
make HOST=i686-pc-linux-gnu;
make HOST=x86_64-w64-mingw32;
make HOST=i686-w64-mingw32;
make HOST=aarch64-linux-gnu;
make HOST=arm-linux-gnueabihf;
make HOST=x86_64-apple-darwin11;
make HOST=host-platform-triplet;

cd ..;
# x86_64-pc-linux-gnu
./autogen.sh;
./configure --prefix=`pwd`/depends/x86_64-pc-linux-gnu
make
mkdir -p build/v0.0.0.1/x86_64-pc-linux-gnu;
cp ./src/donated ./build/v0.0.0.1/x86_64-pc-linux-gnu/donated;
cp ./src/qt/donate-qt ./build/v0.0.0.1/x86_64-pc-linux-gnu/donate-qt;
strip ./build/v0.0.0.1/x86_64-pc-linux-gnu/donated
strip ./build/v0.0.0.1/x86_64-pc-linux-gnu/donate-qt
## created detached signatures
cd build/v0.0.0.1/x86_64-pc-linux-gnu;

gpg --detach-sign -o donate-qt.sig donate-qt
gpg --verify donate-qt.sig

gpg --armor --detach-sign -o donated.sig donated
gpg --verify donated.sig
cd ../../..;

make clean;cd src;make clean;cd ..;

# i686-pc-linux-gnu
./autogen.sh;
./configure --prefix=`pwd`/depends/i686-pc-linux-gnu
make
mkdir -p build/v0.0.0.1/i686-pc-linux-gnu;
cp ./src/donated ./build/v0.0.0.1/i686-pc-linux-gnu/donated;
cp ./src/qt/donate-qt ./build/v0.0.0.1/i686-pc-linux-gnu/donate-qt;
strip ./build/v0.0.0.1/i686-pc-linux-gnu/donated
strip ./build/v0.0.0.1/i686-pc-linux-gnu/donate-qt
# created detached signatures
cd build/v0.0.0.1/i686-pc-linux-gnu;

gpg --detach-sign -o donate-qt.sig donate-qt
gpg --verify donate-qt.sig

gpg --armor --detach-sign -o donated.sig donated
gpg --verify donated.sig
cd ../../..;

make clean;cd src;make clean;cd ..;

# x86_64-w64-mingw32
./autogen.sh;
./configure --prefix=`pwd`/depends/x86_64-w64-mingw32
make HOST=x86_64-w64-mingw32

mkdir -p build/v0.0.0.1/x86_64-w64-mingw32;
cp ./src/donated.exe ./build/v0.0.0.1/x86_64-w64-mingw32/donated.exe;
cp ./src/qt/donate-qt.exe ./build/v0.0.0.1/x86_64-w64-mingw32/donate-qt.exe;
strip ./build/v0.0.0.1/x86_64-w64-mingw32/donated.exe
strip ./build/v0.0.0.1/x86_64-w64-mingw32/donate-qt.exe
## created detached signatures
cd build/v0.0.0.1/x86_64-w64-mingw32;


##/C= 	Country 	GB
##/ST= 	State 	London
##/L= 	Location 	London
##/O= 	Organization 	Global Security
##/OU= 	Organizational Unit 	IT Department
##/CN= 	Common Name 	example.com

openssl req -x509 -nodes -days 365 -newkey rsa:4096 -keyout ./donate-qt-selfsigned.key -out ./donate-qt-selfsigned.crt -subj "/C=AT/ST=Vienna/L=Vienna/O=Development/OU=Core Development/CN=edonatecore.com";
openssl req -x509 -nodes -days 365 -newkey rsa:4096 -keyout ./donated-selfsigned.key -out ./donated-selfsigned.crt -subj "/C=AT/ST=Vienna/L=Vienna/O=Development/OU=Core Development/CN=edonatecore.com";

osslsigncode sign -certs donate-qt-selfsigned.crt -key donate-qt-selfsigned.key \
        -n "Donate Core source code" -i http://www.donatecore.com/ \
        -t http://timestamp.verisign.com/scripts/timstamp.dll \
        -in donate-qt.exe -out donate-qt-signed.exe

osslsigncode sign -certs donated-selfsigned.crt -key donated-selfsigned.key \
        -n "Donate Core source code" -i http://www.donatecore.com/ \
        -t http://timestamp.verisign.com/scripts/timstamp.dll \
        -in donated.exe -out donated-signed.exe

mv donate-qt-signed.exe donate-qt.exe;
mv donated-signed.exe donated.exe;

cd ../../..;
make clean;cd src;make clean;cd ..;

# i686-w64-mingw32
./autogen.sh;
./configure --prefix=`pwd`/depends/i686-w64-mingw32
make HOST=i686-w64-mingw32

mkdir -p build/v0.0.0.1/i686-w64-mingw32;
cp ./src/donated.exe ./build/v0.0.0.1/i686-w64-mingw32/donated.exe;
cp ./src/qt/donate-qt.exe ./build/v0.0.0.1/i686-w64-mingw32/donate-qt.exe;
strip ./build/v0.0.0.1/i686-w64-mingw32/donated.exe
strip ./build/v0.0.0.1/i686-w64-mingw32/donate-qt.exe
## created detached signatures
cd build/v0.0.0.1/i686-w64-mingw32;

##/C= 	Country 	GB
##/ST= 	State 	London
##/L= 	Location 	London
##/O= 	Organization 	Global Security
##/OU= 	Organizational Unit 	IT Department
##/CN= 	Common Name 	example.com

openssl req -x509 -nodes -days 365 -newkey rsa:4096 -keyout ./donate-qt-selfsigned.key -out ./donate-qt-selfsigned.crt -subj "/C=AT/ST=Vienna/L=Vienna/O=Development/OU=Core Development/CN=edonatecore.com";
openssl req -x509 -nodes -days 365 -newkey rsa:4096 -keyout ./donated-selfsigned.key -out ./donated-selfsigned.crt -subj "/C=AT/ST=Vienna/L=Vienna/O=Development/OU=Core Development/CN=edonatecore.com";

osslsigncode sign -certs donate-qt-selfsigned.crt -key donate-qt-selfsigned.key \
        -n "Donate Core source code" -i http://www.donatecore.com/ \
        -t http://timestamp.verisign.com/scripts/timstamp.dll \
        -in donate-qt.exe -out donate-qt-signed.exe

osslsigncode sign -certs donated-selfsigned.crt -key donated-selfsigned.key \
        -n "Donate Core source code" -i http://www.donatecore.com/ \
        -t http://timestamp.verisign.com/scripts/timstamp.dll \
        -in donated.exe -out donated-signed.exe

mv donate-qt-signed.exe donate-qt.exe;
mv donated-signed.exe donated.exe;

cd ../../..;
make clean;cd src;make clean;cd ..;

./autogen.sh;
./configure --prefix=`pwd`/depends/arm-linux-gnueabihf
make HOST=arm-linux-gnueabihf;

mkdir -p build/v0.0.0.1/arm-linux-gnueabihf;
cp ./src/donated ./build/v0.0.0.1/arm-linux-gnueabihf/donated;
cp ./src/qt/donate-qt ./build/v0.0.0.1/arm-linux-gnueabihf/donate-qt;
strip ./build/v0.0.0.1/arm-linux-gnueabihf/donated
strip ./build/v0.0.0.1/arm-linux-gnueabihf/donate-qt
# created detached signatures
cd build/v0.0.0.1/arm-linux-gnueabihf;

gpg --detach-sign -o donate-qt.sig donate-qt
gpg --verify donate-qt.sig

gpg --armor --detach-sign -o donated.sig donated
gpg --verify donated.sig
cd ../../..;


make clean;cd src;make clean;cd ..;

# aarch64-linux-gnu
./autogen.sh;
./configure --prefix=`pwd`/depends/aarch64-linux-gnu
make HOST=aarch64-linux-gnu;

mkdir -p build/v0.0.0.1/aarch64-linux-gnu;
cp ./src/donated ./build/v0.0.0.1/aarch64-linux-gnu/donated;
cp ./src/qt/donate-qt ./build/v0.0.0.1/aarch64-linux-gnu/donate-qt;
strip ./build/v0.0.0.1/aarch64-linux-gnu/donated
strip ./build/v0.0.0.1/aarch64-linux-gnu/donate-qt
# created detached signatures
cd build/v0.0.0.1/aarch64-linux-gnu;

gpg --detach-sign -o donate-qt.sig donate-qt
gpg --verify donate-qt.sig

gpg --armor --detach-sign -o donated.sig donated
gpg --verify donated.sig
cd ../../..;

# arm-linux-gnueabihf
./autogen.sh;
./configure --prefix=`pwd`/depends/arm-linux-gnueabihf
make
mkdir -p build/v0.0.0.1/arm-linux-gnueabihf;
cp ./src/donated ./build/v0.0.0.1/arm-linux-gnueabihf/donated;
cp ./src/qt/donate-qt ./build/v0.0.0.1/arm-linux-gnueabihf/donate-qt;
strip ./build/v0.0.0.1/arm-linux-gnueabihf/donated
strip ./build/v0.0.0.1/arm-linux-gnueabihf/donate-qt
## created detached signatures
cd build/v0.0.0.1/arm-linux-gnueabihf;

gpg --detach-sign -o donate-qt.sig donate-qt
gpg --verify donate-qt.sig

gpg --armor --detach-sign -o donated.sig donated
gpg --verify donated.sig
cd ../../..;

make clean;cd src;make clean;cd ..;

# host-platform-triplet
./autogen.sh;
./configure --prefix=`pwd`/depends/host-platform-triplet
make
mkdir -p build/v0.0.0.1/host-platform-triplet;
cp ./src/donated ./build/v0.0.0.1/host-platform-triplet/donated;
cp ./src/qt/donate-qt ./build/v0.0.0.1/host-platform-triplet/donate-qt;
strip ./build/v0.0.0.1/host-platform-triplet/donated
strip ./build/v0.0.0.1/host-platform-triplet/donate-qt
## created detached signatures
cd build/v0.0.0.1/host-platform-triplet;

gpg --detach-sign -o donate-qt.sig donate-qt
gpg --verify donate-qt.sig

gpg --armor --detach-sign -o donated.sig donated
gpg --verify donated.sig
cd ../../..;

make clean;cd src;make clean;cd ..;

# x86_64-apple-darwin11
./autogen.sh;
./configure --prefix=`pwd`/depends/x86_64-apple-darwin11
make HOST=x86_64-apple-darwin11;

#mkdir -p build/v0.0.0.1/x86_64-apple-darwin11;
#cp ./src/donated ./build/v0.0.0.1/x86_64-apple-darwin11/donated;
#cp ./src/qt/donate-qt ./build/v0.0.0.1/x86_64-apple-darwin11/donate-qt;
#strip ./build/v0.0.0.1/x86_64-apple-darwin11/donated
#strip ./build/v0.0.0.1/x86_64-apple-darwin11/donate-qt
# created detached signatures
#cd build/v0.0.0.1/x86_64-apple-darwin11;

#gpg --detach-sign -o donate-qt.sig donate-qt
#gpg --verify donate-qt.sig

#gpg --armor --detach-sign -o donated.sig donated
#gpg --verify donated.sig
#cd ../../..;


#make clean;cd src;make clean;cd ..;