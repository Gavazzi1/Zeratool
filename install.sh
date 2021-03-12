#!/bin/bash
apt-get install python-pip python-dev build-essential rubygems-integration ruby-dev rubygems python-dev libffi-dev -y
#Ubuntu 12 -> rubygems
#Ubuntu 14 -> rubygems-integration
#Ubuntu 16,18 -> ruby-dev

dpkg --add-architecture i386
apt-get update
apt-get install libc6:i386 libstdc++6:i386 -y

 
pip install virtualenv virtualenvwrapper
 
pip install --upgrade pip
  
printf '\n%s\n%s\n%s' '# virtualenv' 'export WORKON_HOME=~/virtualenvs' 'source /usr/local/bin/virtualenvwrapper.sh' >> ~/.bashrc

export WORKON_HOME=~/virtualenvs
source /usr/local/bin/virtualenvwrapper.sh
 
mkvirtualenv zeratool

workon zeratool

gem install one_gadget

#Need to port to latest angr
pip install angr==7.8.2.21 cffi==1.7.0 future==0.16.0 pycparser==2.18  IPython==5.0 r2pipe psutil timeout_decorator pwn

git clone https://github.com/radare/radare2.git

./radare2/sys/install.sh

pip install IPython==5.0 r2pipe psutil timeout_decorator pwn

echo "####################"
echo "run: . ~/.bashrc"
echo "run: workon zeratool"
