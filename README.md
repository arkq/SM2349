# SM2, SM3, SM4, SM9 and ZUC

This repository contains GM/T serial standards implementations (SM2, SM3, SM4,
SM9 and ZUC) provided by the [Commercial Cryptography Testing
Center](http://www.scctc.org.cn/templates/Download/index.aspx?nodeid=71).

Every source code in this repository can be used for academic, non-profit
making or non-commercial use only. All implementation are based on [MIRACL
Cryptographic SDK](https://miracl.com/), which also requires a proper license
which may be obtained from Shamus Software Ltd.

## Usage

1. Clone this repository with Git submodules:

   ```sh
   git clone https://github.com/Arkq/SM2349.git && cd SM2349
   git submodule update --init --recursive
   ```

2. Build MIRACL library:

   **NOTE:** This step will compile MIRACL library for x64 Linux platforms
   only. If your target/host platform is different, please compile MIRACL library by
   yourself - refer to the documentation provided by the MIRACL library codebase.

   ```sh
   make miracl.a
   ```

3. Build SM algorithms reference implementations:

   ```sh
   make
   ```
