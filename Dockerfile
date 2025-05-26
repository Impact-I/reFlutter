FROM ubuntu:22.04

ARG HASH_PATCH
ARG COMMIT
ARG arm
ARG arm64
ARG x64

ENV DEPOT_TOOLS_PATH=/depot_tools
ENV TEMP_ENGINE=/engine
ENV ENGINE_PATH=/customEngine
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/depot_tools
ENV WAIT=4
ENV arm64=${arm64:-arm64-v8a}
ENV arm=${arm:-armeabi-v7a}
ENV x64=${x64:-x86_64}
ENV HASH_PATCH=$HASH_PATCH
ENV COMMIT=$COMMIT

RUN apt-get update && \
  DEBIAN_FRONTEND="noninteractive" apt-get install -y \
  git \
  wget \
  curl \
  software-properties-common \
  ninja-build \
  unzip \
  python3-pip \
  python3 \
  lsb-release \
  sudo \
  apt-transport-https \
  tzdata \
  python3-pkgconfig \
  default-jre \
  default-jdk \
  && rm -rf /var/lib/apt/lists/* \
  && mkdir t

COPY entrypoint.sh .

ENTRYPOINT ["/bin/sh", "-c", "entrypoint.sh"]

CMD ["bash"]
