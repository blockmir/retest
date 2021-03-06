#!/bin/bash

clear
cd /root
echo && echo
echo "██╗    ██╗███████╗██╗      ██████╗ ██████╗ ███╗   ███╗███████╗    ████████╗ ██████╗ "
echo "██║    ██║██╔════╝██║     ██╔════╝██╔═══██╗████╗ ████║██╔════╝    ╚══██╔══╝██╔═══██╗"
echo "██║ █╗ ██║█████╗  ██║     ██║     ██║   ██║██╔████╔██║█████╗         ██║   ██║   ██║"
echo "██║███╗██║██╔══╝  ██║     ██║     ██║   ██║██║╚██╔╝██║██╔══╝         ██║   ██║   ██║"
echo "╚███╔███╔╝███████╗███████╗╚██████╗╚██████╔╝██║ ╚═╝ ██║███████╗       ██║   ╚██████╔╝"
echo " ╚══╝╚══╝ ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝       ╚═╝    ╚═════╝ "
echo "                                                                                    "
echo "            ███╗   ███╗███╗  ██╗ █████╗  ██████╗ ██████╗ ██╗███╗  ██╗               "
echo "            ████╗ ████║████╗ ██║██╔══██╗██╔════╝██╔═══██╗██║████╗ ██║               "
echo "            ██╔████╔██║██╔█████║███████║██║     ██║   ██║██║██╔█████║               "
echo "            ██║╚██╔╝██║██║╚████║██╔════╝██║     ██║   ██║██║██║╚████║               "
echo "            ██║ ╚═╝ ██║██║ ╚═██║██║     ╚██████╗╚██████╔╝██║██║ ╚═██║               "
echo "            ╚═╝     ╚═╝╚═╝   ╚═╝╚═╝      ╚═════╝ ╚═════╝ ╚═╝╚═╝   ╚═╝               "
                                                                                        
echo && echo && echo
sleep 2

# Check if is root
if [ "$(whoami)" != "root" ]; then
  echo "Script must be run as user: root"
  exit -1
fi

# Check for systemd
systemctl --version >/dev/null 2>&1 || { echo "You must use Ubuntu 16.04 (Xenial)."  >&2; exit 1; }

# Gather input from user
echo "Please enter your Masternode Private Key"
read -e -p "e.g. (8tagsuahsAHAJshjvhs88asadijsuyas98aqsaziucdplmkh75sb) : " key
if [[ "$key" == "" ]]; then
    echo "WARNING: No private key entered, exiting!!!"
    echo && exit
fi
read -e -p "VPS Server IP Address and Masternode RPC Port like IP:11000 : " ip
echo && echo "Pressing ENTER will use the default value for the next prompts."
echo && sleep 3
read -e -p "Add swap space? (Recommended) [Y/n] : " add_swap
if [[ ("$add_swap" == "y" || "$add_swap" == "Y" || "$add_swap" == "") ]]; then
    read -e -p "Swap Size [2G] : " swap_size
    if [[ "$swap_size" == "" ]]; then
        swap_size="2G"
    fi
fi
read -e -p "Install Fail2ban? (Recommended) [Y/n] : " install_fail2ban

# Add swap if needed
if [[ ("$add_swap" == "y" || "$add_swap" == "Y" || "$add_swap" == "") ]]; then
    if [ ! -f /swapfile ]; then
        echo && echo "Adding swap space..."
        sleep 3
        sudo fallocate -l $swap_size /swapfile
        sudo chmod 600 /swapfile
        sudo mkswap /swapfile
        sudo swapon /swapfile
        echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
        sudo sysctl vm.swappiness=10
        sudo sysctl vm.vfs_cache_pressure=50
        echo 'vm.swappiness=10' | sudo tee -a /etc/sysctl.conf
        echo 'vm.vfs_cache_pressure=50' | sudo tee -a /etc/sysctl.conf
    else
        echo && echo "WARNING: Swap file detected, skipping add swap!"
        sleep 3
    fi
fi

# Update system
echo && echo "Upgrading system and install initial dependencies"
sleep 3
sudo apt -y update
sudo apt -y upgrade

# Install required packages
echo && echo "Installing base packages..."
sleep 3
sudo apt -y install \
build-essential \
libtool \
autotools-dev \
automake \
unzip \
pkg-config \
libssl-dev \
bsdmainutils \
software-properties-common \
libzmq3-dev \
libevent-dev \
libboost-dev \
libboost-chrono-dev \
libboost-filesystem-dev \
libboost-program-options-dev \
libboost-system-dev \
libboost-test-dev \
libboost-thread-dev \
libdb4.8-dev \
libdb4.8++-dev \
libminiupnpc-dev \
python-virtualenv

# Install fail2ban if needed
if [[ ("$install_fail2ban" == "y" || "$install_fail2ban" == "Y" || "$install_fail2ban" == "") ]]; then
    echo && echo "Installing fail2ban..."
    sleep 3
    sudo apt -y install fail2ban
    sudo service fail2ban restart
fi

# Edit/Create config file for Donate
echo && echo "Creating your data folder and files..."
sleep 3
sudo mkdir /root/.donate

rpcuser=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1`
rpcpassword=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1`
sudo touch /root/.donate/donate.conf
echo '
rpcuser='$rpcuser'
rpcpassword='$rpcpassword'
rpcallowip=127.0.0.1
listen=1
server=1
rpcport=11000
daemon=1
logtimestamps=1
maxconnections=256
externalip='$ip'
masternode=1
masternodeprivkey='$key'
' | sudo -E tee /root/.donate/donate.conf


# Download binaries for Linux
mkdir donate
wget https://github.com/MasterNodesPro/Donate/releases/download/v1.2.0/donate-1.2.0-ubuntu-no-gui.tar.gz -O donate-1.2.0-ubuntu-no-gui.tar.gz
#unzip donate-v1.1.0.zip -D donate
tar xzvf donate-1.2.0-ubuntu-no-gui.tar.gz -C donate
cd donate
# Give permissions, move to bin folder and run
chmod +x donated
chmod +x donate-cli
chmod +x donate-tx

# Move binaries do lib folder
sudo mv donate-cli /usr/local/bin/donate-cli
sudo mv donate-tx /usr/local/bin/donate-tx
sudo mv donated /usr/local/bin/donated

#run daemon
donated -daemon
sleep 5

# Create a cronjob for making sure donated runs after reboot
if ! crontab -l | grep "@reboot donated -daemon"; then
  (crontab -l ; echo "@reboot donated -daemon") | crontab -
fi

# Finished
echo && echo "Donate Masternode Setup Complete!"

echo "If you put correct PrivKey and VPS IP the daemon should be running."
echo "Wait 2 minutes then run donate-cli getinfo to check blocks."
echo "When fully synced you can start ALIAS on local wallet and finally check here with donate-cli masternode status."
echo && echo
