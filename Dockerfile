
FROM tozd/sgx:ubuntu-xenial

WORKDIR /app/bin

ADD . /app/sgx-src

ADD docker_build_sgx.sh /app
ADD docker_entry.sh /app/bin

EXPOSE 80

RUN apt-get update && apt-get install -y \
  libssl-dev

RUN /app/docker_build_sgx.sh

ENTRYPOINT ["/app/bin/docker_entry.sh"]