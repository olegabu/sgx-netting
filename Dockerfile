
FROM tozd/sgx:ubuntu-xenial

WORKDIR /app

ADD . /src

ADD cmake-build-debug/bin /app

ADD docker_entry.sh /app

EXPOSE 80

RUN apt-get update && apt-get install -y \
  libssl-dev
ENTRYPOINT /app/docker_entry.sh