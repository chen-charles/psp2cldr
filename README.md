psp2cldr - PSP2 Custom Loader
========

Loading *userspace* PSP2 VELFs.  

## Native
**psp2cldr** runs directly on arm32v7-linux  
### via QEMU System Emulation
`virt` platform with `smp=4` and `4G` memory  
   * `ubuntu:bionic` now has `cmake` from [Kitware APT Repository](https://apt.kitware.com/) too.  
   * `ubuntu:focal` upgraded from `bionic` `netboot` installation on `virt` platform with `smp=4` and `4G` memory.  
      * make sure `/boot` has `1G`, otherwise the upgrade would fail.  

### via Docker
`glibc` is required.  
Noticed a memory leak, but it doesn't reproduce on full system emulation. Verified with `heaptrack`/`jemalloc` and `psp2cldr`'s `mmap` calls, seems it isn't caused by `psp2cldr`. Would be a good verification platform to work with, but be aware of this potential leakage.  
#### `arm32v7/fedora:33`  
   * Recommended, comes with a working CMake, GCC 10.  
#### `arm32v7/ubuntu:focal`
   * CMake 3.16 has a [bug](https://gitlab.kitware.com/cmake/cmake/-/issues/20568) that renders it unusable on armhf, you can either cross-compile ([GNU Toolchain for the A-profile Architecture](https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-a/downloads)), build CMake 3.18+ from source, or use the [Kitware APT Repository](https://apt.kitware.com/) (*had no luck though).  

## Usage
   1. Displaying information of the supplied VELF  
   `psp2cldr --readelf XXX.velf`
   2. Load VELF (see usage via `psp2cldr -h`)  

## Supplementary ELFs
**psp2cldr** provides a mechanism to load supplementary ELFs into the address space of the target. `DT_NEEDED` tag is respected.  
Supplementary ELFs need to be built for the target platform. [A custom toolchain](https://github.com/chen-charles/buildscripts) has been assembled to permit `C`(`newlib` + `pthread-embedded`) and `C++` library usages.  
```bash
arm-vita-eabi-g++ -shared a.cc -o supp_elf.so
```
The following libraries need to be loaded from the toolchain,
```
libc.so
libm.so
libpthread.so
libgcc_s.so
libstdc++.so
```
   
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
