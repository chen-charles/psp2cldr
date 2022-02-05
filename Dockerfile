FROM arm32v7/fedora:34

RUN dnf check-update; exit 0
RUN dnf install -y cmake gcc gcc-c++ spdlog-devel

COPY . /src

# https://bugzilla.redhat.com/show_bug.cgi?id=1906956
RUN ln -s /usr/bin/armv7hl-redhat-linux-gnueabi-pkg-config /usr/bin/armv7hnl-redhat-linux-gnueabi-pkg-config

RUN cd /src
RUN cmake -S /src -B /src/build
RUN cmake --build /src/build --parallel $(nproc)
RUN cmake --build /src/build --parallel $(nproc) --target install
RUN cmake --build /src/build --parallel $(nproc) --target clean
