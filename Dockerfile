FROM arm32v7/fedora:33

RUN dnf check-update; exit 0
RUN dnf install -y spdlog-devel cmake gcc gcc-c++
RUN git clone https://github.com/chen-charles/psp2cldr.git && \
    cd psp2cldr && mkdir build && cd build && cmake .. && make
