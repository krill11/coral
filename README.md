# CoralOS

A minimal operating system built for learning and experimentation.

## Building from Source

### Prerequisites

- Windows:
  - Windows Subsystem for Linux (WSL) or Cygwin/MSYS2
  - GCC cross-compiler
  - NASM
  - QEMU (for testing)

- Linux:
  - GCC
  - NASM
  - QEMU (for testing)

### Building

1. Clone the repository:
```bash
git clone https://github.com/yourusername/CoralOS.git
cd CoralOS
```

2. Build the OS:
```bash
make
```

3. Run in QEMU:
```bash
qemu-system-i386 -fda os.img
```

## Using Pre-built Releases

The easiest way to get started with CoralOS is to use a pre-built release:

1. Go to the [Releases](https://github.com/yourusername/CoralOS/releases) page
2. Download the latest `coralos.iso` file
3. Run in QEMU:
```bash
qemu-system-i386 -cdrom coralos.iso
```

## Features

- Protected mode kernel
- Memory management with paging
- Process management
- File system support
- Dynamic linking
- Terminal with job control
- Bash shell

## Project Structure

```
CoralOS/
├── boot/           # Bootloader
├── kernel/         # Kernel source
│   ├── drivers/    # Device drivers
│   ├── fs/         # File system
│   ├── mm/         # Memory management
│   └── proc/       # Process management
├── libc/           # C library
├── initrd/         # Initial ramdisk
└── tools/          # Build tools
```

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 