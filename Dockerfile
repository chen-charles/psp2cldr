FROM arm32v7/fedora:34

RUN dnf check-update; exit 0
RUN dnf install -y cmake gcc gcc-c++ spdlog-devel

COPY . /src
RUN cd /src
RUN cmake -S /src -B /src/build
RUN cmake --build /src/build --parallel $(nproc)
RUN cmake --build /src/build --parallel $(nproc) --target install
RUN cmake --build /src/build --parallel $(nproc) --target clean
