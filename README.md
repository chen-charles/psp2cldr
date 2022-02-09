psp2cldr - PSP2 Custom Loader
========

Loading *userspace* PSP2 VELFs.  

## Native
**psp2cldr** runs directly on arm32v7-linux  
### via QEMU System Emulation
`virt` platform with `smp=4` and `4G` memory  

### via [QEMU User Mode Emulation (qemu-linux-user)](User.Dockerfile)  
*Memory leak is under investigation [#2](https://github.com/chen-charles/psp2cldr/issues/2).*  
`arm-none-linux-gnueabihf`  
Make sure to use a **recent** release of `qemu-arm`.  (for the record, `qemu-arm version 2.11.1` is not one of them).  
Tested with `qemu-arm version 6.1.0 (qemu-6.1.0-10.fc35)`.  

### via [Docker](Dockerfile)  
*Memory leak is under investigation [#2](https://github.com/chen-charles/psp2cldr/issues/2).*  
#### `arm32v7/fedora:33`, `arm32v7/fedora:34`, `arm32v7/fedora:35`  
   * Recommended, comes with a working CMake, GCC 10/11.  
#### `arm32v7/ubuntu:focal`
   * CMake 3.16 has a [bug](https://gitlab.kitware.com/cmake/cmake/-/issues/20568) that renders it unusable on armhf, you can either cross-compile ([GNU Toolchain for the A-profile Architecture](https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-a/downloads)), build CMake 3.18+ from source, or use the [Kitware APT Repository](https://apt.kitware.com/) (*had no luck though).  

## Usage
   1. Displaying information of the supplied VELF  
   `psp2cldr --readelf XXX.velf`
   2. Load ELFs, and optionally VELFs (see usage via `psp2cldr -h`)  

## Routine Providers
See [Guide](sample_implementations/README.md)  
See [Sample](sample_implementations/dynamic/impl.cc)  
See [psp2cldr Newlib OS Support Reference Implementation](https://github.com/chen-charles/psp2cldr-NewlibOSL)  

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
   * Only relocation type `0` and `1` are implemented. User VELFs tend to not use types `2` to `9`.  

## Dependencies
Installed automatically if not found  
 * [spdlog v1.x](https://github.com/gabime/spdlog/tree/v1.x)  

## Building
See [Dockerfile](Dockerfile)  

## License
MIT
