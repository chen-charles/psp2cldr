psp2cldr - PSP2 Custom Loader
========

Loading *userspace* PSP2 VELFs.  

## Native
**psp2cldr** runs directly on arm32v7-linux  

### via Docker
`glibc` is required.  
#### `arm32v7/fedora:33`  
   * Recommended, comes with a working CMake, GCC 10.  
#### `arm32v7/ubuntu:focal`
   * CMake 3.16 has a [bug](https://gitlab.kitware.com/cmake/cmake/-/issues/20568) that renders it unusable on armhf natively, you can either cross-compile ([GNU Toolchain for the A-profile Architecture](https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-a/downloads)), or build CMake 3.18+ from source.  

### via QEMU-user
```bash
sudo apt install qemu-user qemu-user-static gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf binutils-arm-linux-gnueabihf gdb-multiarch
qemu-arm -L /usr/arm-linux-gnueabihf/ ./build/psp2cldr
```

## Usage
   1. Displaying information of the supplied VELF  
   `psp2cldr --readelf XXX.velf`
   2. Load VELF (see usage via `psp2cldr -h`)  

## Supplementary ELFs
**psp2cldr** provides a mechanism to load supplementary ELFs into the address space of the target.  
Supplementary ELFs need to be built for the target platform, with the following options: `-fPIC`, `-shared`, `-nostdlib`, `-lgcc` and `--hash-style=sysv`.  
```bash
arm-vita-eabi-gcc -shared -o libyours.so -Wl,--hash-style=sysv,--whole-archive libyours.a -nostdlib -lgcc
```
Newlib has been compiled [here](https://github.com/chen-charles/psp2cldr-newlib/releases) (all syscalls should be provided from the providers). `thread_basic*` can be tested with the sample dynamic implementation.  
Note: `DT_NEEDED` tag is respected.  

## Known Limitations
   * Only `e_type == ET_SCE_RELEXEC` is supported, partly because in native mode we cannot enforce the binary to be loaded at an exact location.  
   * Only relocation type `0` and `1` is implemented. Games tend to not use types `2` to `9`.  

## Dependencies
 * spdlog v1.x  
   ```sh
   git clone https://github.com/gabime/spdlog && cd spdlog && mkdir build && cd build && cmake .. && make
   sudo make install
   ```

## License
MIT
