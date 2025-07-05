# FreeBSD Build Guide for c2pool

This guide covers building c2pool specifically on FreeBSD systems.

## System Requirements

- FreeBSD 12.0 or later
- CMake 3.22 or later (3.30+ fully supported)
- GCC 11+ or Clang 13+

## Dependencies Installation

Install all required dependencies using the FreeBSD package manager:

```shell
# Core build tools
pkg install cmake
pkg install git

# C++ compiler (if not already installed)
pkg install gcc

# Core libraries
pkg install boost-all
pkg install leveldb
pkg install googletest
pkg install nlohmann-json
pkg install yaml-cpp
```

## Building c2pool

1. Clone the repository:

```shell
git clone https://github.com/frstrtr/c2pool.git
cd c2pool
```

2. Configure and build:

```shell
cmake -DCMAKE_BUILD_TYPE=Debug -S . -B build
make -C build c2pool -j$(nproc)
```

3. The executable will be located at: `./build/src/c2pool/c2pool`

## Configuration

### View current configuration:

```shell
./build/src/c2pool/c2pool --ui_config
```

### Configuration files location:

FreeBSD follows the XDG Base Directory specification:
- Config: `~/.config/c2pool/`
- Data: `~/.local/share/c2pool/`

## Running c2pool

### Start mining pool server:

```shell
./build/src/c2pool/c2pool --web_server=0.0.0.0:8083 --testnet
```

This will start:
- HTTP/JSON-RPC server on port 8083
- Stratum mining server on port 8084 (after blockchain sync)

### Command line options:

```shell
./build/src/c2pool/c2pool --help
```

## FreeBSD-Specific Notes

### Package Management

FreeBSD uses `pkg` for binary packages and `ports` for source compilation:

```shell
# Update package database
pkg update

# Search for packages
pkg search boost

# Install from ports (if binary not available)
cd /usr/ports/devel/boost-all && make install clean
```

### Compiler Selection

If you have multiple compilers installed:

```shell
# Use GCC
export CC=gcc
export CXX=g++

# Or use Clang
export CC=clang
export CXX=clang++
```

### CMake 3.30+ Compatibility

The project automatically handles CMake 3.30+ compatibility where the FindBoost module was removed. No manual configuration required.

### Performance Optimization

For release builds with optimizations:

```shell
cmake -DCMAKE_BUILD_TYPE=Release -S . -B build-release
make -C build-release c2pool -j$(nproc)
```

## Troubleshooting

### Missing Dependencies

If you get missing library errors:

```shell
# Check what's installed
pkg info | grep boost
pkg info | grep cmake

# Install missing packages
pkg install <missing-package>
```

### Compilation Errors

1. **Low memory**: Reduce parallel compilation:
   ```shell
   make -C build c2pool -j1
   ```

2. **Boost not found**: Ensure boost-all is installed:
   ```shell
   pkg install boost-all
   ```

3. **CMake too old**: Update CMake:
   ```shell
   pkg install cmake
   ```

### Runtime Issues

1. **Permission denied**: Make sure the executable is marked executable:
   ```shell
   chmod +x ./build/src/c2pool/c2pool
   ```

2. **Port binding errors**: Ensure ports 8083/8084 are available:
   ```shell
   sockstat -l | grep 808
   ```

## Mining Setup

### Connect miners to c2pool:

- **HTTP miners**: Point to `http://your-ip:8083`
- **Stratum miners**: Point to `your-ip:8084`

### Supported mining protocols:

- getwork/submitwork
- getblocktemplate/submitblock  
- Stratum (mining.subscribe/authorize/submit)

## Integration with FreeBSD Services

### Create a service script (`/usr/local/etc/rc.d/c2pool`):

```shell
#!/bin/sh

. /etc/rc.subr

name="c2pool"
rcvar="${name}_enable"
command="/path/to/c2pool/build/src/c2pool/c2pool"
command_args="--web_server=0.0.0.0:8083 --testnet"
pidfile="/var/run/${name}.pid"
command_background="yes"

load_rc_config $name
run_rc_command "$1"
```

### Enable and start:

```shell
echo 'c2pool_enable="YES"' >> /etc/rc.conf
service c2pool start
```

## Verified FreeBSD Versions

This build has been tested on:
- FreeBSD 13.x with CMake 3.31.6+
- FreeBSD 14.x with CMake 3.31.6+

For older FreeBSD versions, ensure CMake >= 3.22 is available.
