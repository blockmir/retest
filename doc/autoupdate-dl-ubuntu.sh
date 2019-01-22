#!/bin/bash

now=$(date +"%m_%d_%Y")

# Check if is root
if [ "$(whoami)" != "root" ]; then
  echo "Script must be run as user: root"
  exit -1
fi

apt install libzmq3-dev -y

echo && echo "going to root directory"
cd ~/

echo && echo "Stopping daemon..."
donate-cli stop

echo && echo "downloading update"
wget https://github.com/MasterNodesPro/Donate/releases/download/v1.2.0/donate-1.2.0-ubuntu-no-gui.tar.gz -O donate-v1.2.0.tar.gz

mkdir donatebackup && cd $_

mkdir $now

backuppath=~/donatebackup/$now

echo && echo "backing up wallet.dat masternode.conf donate.conf to ${backuppath}"
cd ../.donate
cp wallet.dat $backuppath
cp masternode.conf $backuppath
cp donate.conf $backuppath

cd ~/

echo && echo "unzipping daemons"
mkdir donate-release
tar zxvf donate-v1.2.0.tar.gz -C ~/donate-release
cd donate-release
chmod +x donated
chmod +x donate-cli
chmod +x donate-tx

echo && echo "moving to /usr/bin"
sudo mv donate-cli /usr/local/bin/donate-cli
sudo mv donate-tx /usr/local/bin/donate-tx
sudo mv donated /usr/local/bin/donated

echo && echo "cleaning up"
cd ~/
rm donate-release -rf
rm donate-v1.2.0.tar.gz

echo && echo "starting daemon"
donated