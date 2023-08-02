FROM ubuntu:20.04

RUN cd home

RUN apt update -y
RUN apt install software-properties-common -y
RUN add-apt-repository ppa:deadsnakes/ppa -y
RUN apt install python3.9 python3-venv -y
RUN apt install git -y
RUN apt install radare2 -y
RUN apt install pip -y

RUN git clone https://github.com/UNILESS/nsr_oss.git ./home/code

RUN cd /home/code
RUN python3 -m venv /home/code/venv
RUN pip install -r /home/code/requirements.txt
