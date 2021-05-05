psp2cldr - PSP2 Custom Loader
========

Loading *userspace* PSP2 VELFs.  

## Emulation/Native
**psp2cldr** supports two modes, Native and Emulation.  
   * Emulation: by [Unicorn-1.x](https://www.unicorn-engine.org/)  
   * Native: run directly on arm32v7-linux  

### Native via Docker
`glibc` is required.  
#### `arm32v7/fedora:33`  
   * Recommended, comes with a working CMake, GCC 10.  
#### `arm32v7/ubuntu:focal`
   * CMake 3.16 has a [bug](https://gitlab.kitware.com/cmake/cmake/-/issues/20568) that renders it unusable on armhf natively, you can either cross-compile ([GNU Toolchain for the A-profile Architecture](https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-a/downloads)), or build CMake 3.18+ from source.  
#### `arm32v7/alpine:3.13.5`
   * `musl` does not supply `dlmopen`, so no, and similarly for others.  

## Usage
   1. Displaying information of the supplied VELF  
   `psp2cldr --readelf XXX.velf`
   2. Load VELF (see usage via `psp2cldr -h`)  

## Supplementary ELFs
**psp2cldr** provides a mechanism to load supplementary ELFs into the address space of the target.  
Supplementary ELFs need to be built for the target platform, with the following options: `-fPIC`, `-shared`, `-nostdlib` and `--hash-style=sysv`.  
```bash
arm-vita-eabi-gcc -shared -o libyours.so -Wl,--hash-style=sysv,--whole-archive libyours.a -nostdlib
```

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
 * [Unicorn-1.x](https://www.unicorn-engine.org/) for `PSP2CLDR_EMULATION`  

## License
**GPLv2**  
Mostly due to *Unicorn/QEMU*, albeit it is mostly within `emulation.hpp` and `emulation.cc`.  
Also due to `include/elf.h` for `Windows`.  
Might consider splitting the `Native` portion into its own if sufficient people complain :D  
