FROM arm64v8/ubuntu:22.04

RUN DEBIAN_FRONTEND="noninteractive" apt update
RUN DEBIAN_FRONTEND="noninteractive" apt install -y cmake git crossbuild-essential-armhf

COPY . /src

ENV DESTDIR /psp2cldr

RUN cd /src
RUN cmake -DCMAKE_C_COMPILER=/usr/bin/arm-linux-gnueabihf-gcc -DCMAKE_CXX_COMPILER=/usr/bin/arm-linux-gnueabihf-g++ -S /src -B /src/build
RUN cmake --build /src/build --parallel $(nproc)
RUN cmake --build /src/build --parallel $(nproc) --target install
RUN cmake --build /src/build --parallel $(nproc) --target clean

FROM arm64v8/ubuntu:22.04

RUN DEBIAN_FRONTEND="noninteractive" dpkg --add-architecture armhf
RUN DEBIAN_FRONTEND="noninteractive" apt update
RUN DEBIAN_FRONTEND="noninteractive" apt install -y libc6:armhf libstdc++6:armhf

COPY --from=0 /psp2cldr /
