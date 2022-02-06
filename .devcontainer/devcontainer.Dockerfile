FROM fedora:35

RUN dnf check-update; exit 0
RUN dnf install -y git cmake qemu-user xz python2.7 ncurses-compat-libs gcc gcc-c++ spdlog-devel

# https://bugzilla.redhat.com/show_bug.cgi?id=1906956
RUN ln -s /usr/bin/armv7hl-redhat-linux-gnueabi-pkg-config /usr/bin/armv7hnl-redhat-linux-gnueabi-pkg-config

ENV TOOLCHAIN_PREFIX arm-none-linux-gnueabihf
ENV ARMSDK /${TOOLCHAIN_PREFIX}

RUN curl --output ${TOOLCHAIN_PREFIX}.tar.xz -L 'https://developer.arm.com/-/media/Files/downloads/gnu-a/10.2-2020.11/binrel/gcc-arm-10.2-2020.11-x86_64-arm-none-linux-gnueabihf.tar.xz?revision=d0b90559-3960-4e4b-9297-7ddbc3e52783&la=en&hash=985078B758BC782BC338DB947347107FBCF8EF6B'
RUN mkdir -p ${ARMSDK} && tar xf ${TOOLCHAIN_PREFIX}.tar.xz -C ${ARMSDK} --strip-components=1
RUN rm -rf ${TOOLCHAIN_PREFIX}.tar.xz

ENV SYSROOT ${ARMSDK}/${TOOLCHAIN_PREFIX}/libc
ENV PATH ${ARMSDK}/bin:$PATH
ENV CC ${TOOLCHAIN_PREFIX}-gcc
ENV CXX ${TOOLCHAIN_PREFIX}-g++
ENV DESTDIR ${SYSROOT}
ENV CMAKE_PREFIX_PATH ${SYSROOT}:${SYSROOT}/usr/local
ENV PATH ${ARMSDK}/bin:$PATH

# the target file system needs a way to refer to the project for gdb to properly load library symbols
RUN ln -s /root ${SYSROOT}/root
# similarly, this is for vscode dev container
RUN ln -s /workspaces ${SYSROOT}/workspaces

# Debugger: arm-none-linux-gnueabihf-gdb
RUN echo "set auto-load safe-path /" >> /root/.gdbinit

# qemu-arm -g 45678 -L $SYSROOT ./build/psp2cldr ...
