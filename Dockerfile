FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

ARG UID
ARG GID

RUN apt update && apt install -y wget git build-essential \
    python3 libpython3-dev python3-venv python3-pip curl golang && \
    groupadd -g $GID ubuntu && useradd -m -u $UID -g $GID ubuntu -s /usr/bin/bash

RUN python3 -m venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH"

ENV SEEDEMU_INSIDE_DOCKER="True"

ADD requirements.txt /opt/share/requirements.txt

RUN pip3 install -r /opt/share/requirements.txt

USER ubuntu

ENV PYTHONPATH="/home/ubuntu/seed-emulator:$PYTHONPATH"

WORKDIR /home/ubuntu

CMD ["/bin/bash"]
