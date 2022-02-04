FROM arm32v7/fedora:34

RUN dnf check-update; exit 0
RUN dnf install -y cmake gcc gcc-c++ git

COPY . /src
RUN cd /src && mkdir build && cd build
RUN mkdir /out
RUN cmake -DCMAKE_INSTALL_PREFIX:PATH=/out -DCMAKE_BUILD_TYPE=Release /src
RUN make -j$(nproc)
RUN make -j$(nproc) install

FROM arm32v7/fedora:34
COPY --from=0 /out /usr/
