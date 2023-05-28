FROM armv8 as arm_ubuntu

FROM ubuntu:20.04 as builder

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y clang cmake build-essential

RUN apt-get update && apt-get install -y lld

COPY --from=arm_ubuntu /sysroot.tar.gz /sysroot.tar.gz
RUN mkdir -p /sysroot && tar xf /sysroot.tar.gz -C /sysroot/
COPY --from=multiarch/qemu-user-static:x86_64-aarch64-6.1.0-8 /usr/bin/qemu-aarch64-static /usr/bin/qemu-aarch64-static

COPY flag.txt *.c *.license build.sh /src/
COPY dist /dist

RUN /src/build.sh

CMD ["/bin/bash"]

FROM multiarch/qemu-user-static:x86_64-aarch64-6.1.0-8 as challenge
COPY --from=builder /data /data


CMD ["/data/init_drm","-l","/data/password_for_flag.license","/data/run_prog","/data/password_for_flag.bin"]
