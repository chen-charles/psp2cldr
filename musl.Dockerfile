FROM arm32v7/alpine:3.15

RUN apk add cmake gcc g++ musl-dev make bash git

COPY . /src

ENV DESTDIR /psp2cldr

RUN cd /src
RUN cmake -S /src -B /src/build
RUN cmake --build /src/build --parallel $(nproc)
RUN cmake --build /src/build --parallel $(nproc) --target install
RUN cmake --build /src/build --parallel $(nproc) --target clean

FROM arm32v7/alpine:3.15

RUN apk add --no-cache libstdc++
COPY --from=0 /psp2cldr /
