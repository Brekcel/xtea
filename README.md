# XTEA
This crate provides a Rusty implementation of the XTEA cipher, written in Rust.

This crate also provides convenience methods for ciphering and deciphering `u8` slices
and Read streams.

See <https://en.wikipedia.org/wiki/XTEA> for more information on the XTEA cipher.

## Note:
This crate should only be used if you're working on an existing application that uses XTEA.
If you're wanting to implement an encryption or a cipher system in your project DO NOT USE THIS.

## Documentation:

Run the command `cargo doc` in the directory to generate documentation in ./target/doc/

## Installation

Currently not published on crates.io. To use this crate, add it to your `Cargo.toml` like this:

```toml
[dependencies]
xtea = { git = "https://github.com/Brekcel/xtea" }
```

## Example

```rust
extern crate xtea;
extern crate byteorder;

use xtea::XTEA;
use byteorder::BE;

let input: Box<[u8]> = vec![10u8; 16].into_boxed_slice();

let xtea = XTEA::new([0x1380C5B5, 0x28037DF9, 0x26E314A2, 0xC57684E4]);

let encrypted = {
	let mut output = vec![0u8; input.len()].into_boxed_slice();
	xtea.encipher_u8slice::<BE>(&input, &mut output);
	output
};

let decrypted = {
	let mut output = vec![0u8; input.len()].into_boxed_slice();
	xtea.decipher_u8slice::<BE>(&encrypted, &mut output);
	output
};
assert_eq!(input, decrypted);
```