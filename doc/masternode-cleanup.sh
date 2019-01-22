#/bin/bash

# Check if is root
if [ "$(whoami)" != "root" ]; then
  echo "Script must be run as user: root"
  exit -1
fi

echo && echo "Stopping donate"
donate-cli stop

echo && echo "moving donate executables to another directory"
mv /usr/bin/donated /usr/local/bin/donated
mv /usr/bin/donate-tx /usr/local/bin/donate-tx
mv /usr/bin/donate-cli /usr/local/bin/donate-cli

echo && echo "starting donated"
donated