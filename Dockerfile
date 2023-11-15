FROM ubuntu:22.04 as vul4c_base
LABEL authors="Vul4C" description="Out-of-the-box dependency environment for Vul4C" version="1.0"
RUN  apt-get clean
RUN apt-get update
RUN apt-get install -y wget curl build-essential cmake pkg-config libicu-dev zlib1g-dev libcurl4-openssl-dev libssl-dev ruby-dev ca-certificates curl gnupg git vim

# nodejs
RUN curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
RUN echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list
RUN apt-get update && apt-get install nodejs -y
RUN npm -v
RUN npm install -g tree-sitter-cli@0.20.7

# github-linguist
RUN gem install github-linguist

# miniconda
RUN wget \
    https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh \
    && mkdir /root/.conda \
    && bash Miniconda3-latest-Linux-x86_64.sh -b \
    && rm -f Miniconda3-latest-Linux-x86_64.sh

# java sbt scala
RUN curl -s "https://get.sdkman.io" | bash
RUN bash -c "source $HOME/.sdkman/bin/sdkman-init.sh && sdk install java 17.0.6-amzn && sdk install scala 3.2.2 && sdk install sbt 1.8.2"
ENV PATH=/root/miniconda3/bin:$PATH
ENV PATH=/root/.sdkman/candidates/java/current/bin:$PATH
ENV PATH=/root/.sdkman/candidates/scala/current/bin:$PATH
ENV PATH=/root/.sdkman/candidates/sbt/current/bin:$PATH
RUN conda --version &&  npm -v && java --version && scala --version && github-linguist --version && tree-sitter --version

# clone source code and create new conda env
RUN git clone https://github.com/Icyrockton/Vul4C
WORKDIR /Vul4C
RUN conda env create -f environment.yml
RUN echo "source activate vul4c" > ~/.bashrc
ENV PATH=/root/miniconda3/envs/vul4c/bin:$PATH
RUN pip install -e .