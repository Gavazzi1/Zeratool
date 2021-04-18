FROM ubuntu:20.10
RUN apt update -y

# Installing text editors
RUN apt install vim -y
RUN apt install emacs -y
RUN apt install nano -y
RUN apt install less -y

#Installing networking tools
RUN apt install curl -y
RUN apt install net-tools -y
RUN apt install netcat -y

#Installing Python3
RUN apt install python3 -y
RUN apt install python3-pip -y

#Installing additional tools
RUN apt install git -y
RUN apt install bsdmainutils -y

#Install dependencies
RUN pip3 install angr timeout-decorator r2pipe
RUN pip install r2pipe
RUN pip3 install pwn ropper six==1.12.0
RUN git clone https://github.com/radareorg/radare2 && radare2/sys/install.sh

# download source code
RUN git clone https://github.com/Gavazzi1/Zeratool

#ENTRYPOINT tail -f /dev/null
