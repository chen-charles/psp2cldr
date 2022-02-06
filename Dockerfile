# In the release configuration, we will ship with spdlog we compiled to avoid fetching from dnf.

FROM arm32v7/fedora:35

RUN dnf check-update; exit 0
RUN dnf install -y cmake gcc gcc-c++ git

COPY . /src

# https://bugzilla.redhat.com/show_bug.cgi?id=1906956
RUN ln -s /usr/bin/armv7hl-redhat-linux-gnueabi-pkg-config /usr/bin/armv7hnl-redhat-linux-gnueabi-pkg-config

ENV DESTDIR /psp2cldr

RUN cd /src
RUN cmake -S /src -B /src/build
RUN cmake --build /src/build --parallel $(nproc)
RUN cmake --build /src/build --parallel $(nproc) --target install
RUN cmake --build /src/build --parallel $(nproc) --target clean


FROM arm32v7/fedora:35

COPY --from=0 /psp2cldr /
