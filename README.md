# BLS Key Generator

This tool will generate BLS keys that are compatible with the Chia reference wallet. 
The main advantage of this generator over the built in Chia generator is the use of a second entropy source for seed generation, further distancing the key generated from potential hardware random number generator vulnerabilities.
Additionally, this tool is standalone and does not require any preparation or installation to use.

## Usage
The key generator is simple to use, either downloading the precompiled binaries or compiling your own binary from source. To create a cold wallet, put the binary on a USB flash drive and bring it to a non-connected computer. Run the binary to generate a mnemonic and derive applicable public keys.

The mnemonic/private key are not stored anywhere on the system, but you will be given an option to export the public keys/addresses to a text file in the present working directory. You can write down the mnemonic on a piece of paper, then move the public key text file back to the USB for ease of use on your main computer. The wallet observer key can be used to derive observer wallet addresses for your key, allowing you to monitor all addresses associated with that key at once through services such as https://xchbalance.com.

### Building From Source
To build the binary from source, you will need to install rust. Follow the instructions here: https://www.rust-lang.org/tools/install

Once rust is installed, clone this repository with `git clone https://github.com/scrutinously/key-generator.git` and then `cd key-generator`.

Using `cargo build --release` will compile the release version of the binary to `key-generator/target/release`. If you intend to use it on a system architecture or operating system other than what you're building it on, you will need to cross compile, so use `cargo install cross` to get rust's cross compiler, and install docker if it's not already installed. To build a release for the Raspberry Pi 4 from a desktop PC for example, you would then need to run `cross build --target aarch64-unknown-linux-musl --release`.