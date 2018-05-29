/*!
This crate provides a Rusty implementation of the XTEA cipher, written in Rust.

This crate also provides convenience methods for ciphering and deciphering `u8` slices
and Read streams.
*/

extern crate byteorder;

use byteorder::{ByteOrder, ReadBytesExt, WriteBytesExt};
use std::{io::{Read, Result, Write}, io::Cursor, num::Wrapping};

/// Struct containing the `XTEA` info.
/// See <https://en.wikipedia.org/wiki/XTEA> for more information
#[derive(Debug)]
pub struct XTEA {
	key: [Wrapping<u32>; 4],
	num_rounds: Wrapping<u32>,
}

/// Reccomended default number of rounds
const DEFAULT_ROUNDS: u32 = 32;

/// Magic number specified by the algorithm
const DELTA: Wrapping<u32> = Wrapping(0x9E3779B9);

impl XTEA {
	/// Creates a new `XTEA` cipher using the given key.
	#[inline]
	pub fn new(key: [u32; 4]) -> Self {
		Self::new_with_rounds(key, DEFAULT_ROUNDS)
	}

	/// Creates a new XTEA cipher using the given key, with a custom number of rounds.
	///
	/// **HIGHLY Recommended** to use the fn `new(key: [u32; 4]) -> Self` instead unless you know what you're doing.
	///
	/// # Panics
	///
	/// If num_rounds is NOT divisible by 2.
	#[inline]
	pub fn new_with_rounds(key: [u32; 4], num_rounds: u32) -> Self {
		assert_eq!(num_rounds & 1, 0, "num_rounds was not divisible by 2.");
		let key = [Wrapping(key[0]), Wrapping(key[1]), Wrapping(key[2]), Wrapping(key[3])];
		let num_rounds = Wrapping(num_rounds);
		XTEA {
			key,
			num_rounds,
		}
	}

	/// Enciphers the two given `u32`'s into the output array.
	///
	/// Highly recommended to NOT use this, and instead use either the slice or stream implementation.
	///
	/// See <https://en.wikipedia.org/wiki/XTEA#Implementations> for implementation details
	#[inline]
	pub fn encipher(&self, input: &[u32; 2], output: &mut [u32; 2]) {
		let mut v0 = Wrapping(input[0]);
		let mut v1 = Wrapping(input[1]);
		let mut sum = Wrapping(0u32);

		for _ in 0..self.num_rounds.0 as u32 {
			v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + self.key[(sum.0 & 3) as usize]);
			sum += DELTA;
			v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + self.key[((sum.0 >> 11) & 3) as usize]);
		}

		output[0] = v0.0;
		output[1] = v1.0;
	}

	/// Deciphers the two given `u32`'s into the output array.
	///
	/// Highly recommended to NOT use this, and instead use either the slice or stream implementation.
	///
	/// See <https://en.wikipedia.org/wiki/XTEA#Implementations> for implementation details
	#[inline]
	pub fn decipher(&self, input: &[u32; 2], output: &mut [u32; 2]) {
		let mut v0 = Wrapping(input[0]);
		let mut v1 = Wrapping(input[1]);
		let mut sum = DELTA * self.num_rounds;

		for _ in 0..self.num_rounds.0 as u32 {
			v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + self.key[((sum.0 >> 11) & 3) as usize]);
			sum -= DELTA;
			v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + self.key[(sum.0 & 3) as usize]);
		}

		output[0] = v0.0;
		output[1] = v1.0;
	}

	/// Enciphers the given `&[u8]` into the output `&mut [u8]`.
	///
	/// Uses the given [ByteOrder](https://docs.rs/byteorder) passed as a template for properly parsing the slices.
	///
	/// If you're unsure which ByteOrder to use, use `BigEndian` (BE).
	///
	/// # Panics
	///
	/// If the length of the input is not equal to the length of the output
	///
	/// If the length of the input or output is not divisible by 8
	///
	/// # Examples
	///
	/// ```
	/// extern crate xtea;
	/// extern crate byteorder;
	///
	/// use xtea::XTEA;
	///	use byteorder::BE;
	///
	/// let input: Box<[u8]> = vec![10u8; 16].into_boxed_slice();
	///
	///	let xtea = XTEA::new([0x1380C5B5, 0x28037DF9, 0x26E314A2, 0xC57684E4]);
	///
	///	let encrypted = {
	///		let mut output = vec![0u8; input.len()].into_boxed_slice();
	///		xtea.encipher_u8slice::<BE>(&input, &mut output);
	///		output
	///	};
	/// ```
	///
	#[inline]
	pub fn encipher_u8slice<B: ByteOrder>(&self, input: &[u8], output: &mut [u8]) {
		self.cipher_u8slice::<B>(input, output, true)
	}

	/// Deciphers the given `&[u8]` into the output `&mut [u8]`.
	///
	/// Uses the given [ByteOrder](https://docs.rs/byteorder) passed as a template for properly parsing the slices.
	///
	/// If you're unsure which ByteOrder to use, use `BigEndian` (BE).
	///
	/// # Panics
	///
	/// If the length of the input is not equal to the length of the output.
	///
	/// If the length of the input or output is not divisible by 8.
	///
	/// # Examples
	///
	/// ```
	/// extern crate xtea;
	/// extern crate byteorder;
	///
	/// use xtea::XTEA;
	///	use byteorder::BE;
	///
	/// let input: Box<[u8]> = vec![10u8; 16].into_boxed_slice();
	///
	///	let xtea = XTEA::new([0x1380C5B5, 0x28037DF9, 0x26E314A2, 0xC57684E4]);
	///
	///	let encrypted = {
	///		let mut output = vec![0u8; input.len()].into_boxed_slice();
	///		xtea.encipher_u8slice::<BE>(&input, &mut output);
	///		output
	///	};
	///
	/// let decrypted = {
	/// 	let mut output = vec![0u8; input.len()].into_boxed_slice();
	/// 	xtea.decipher_u8slice::<BE>(&encrypted, &mut output);
	/// 	output
	/// };
	/// assert_eq!(input, decrypted);
	/// ```
	///
	#[inline]
	pub fn decipher_u8slice<B: ByteOrder>(&self, input: &[u8], output: &mut [u8]) {
		self.cipher_u8slice::<B>(input, output, false)
	}

	#[inline]
	fn cipher_u8slice<B: ByteOrder>(&self, input: &[u8], output: &mut [u8], encipher: bool) {
		assert_eq!(input.len(), output.len(), "The input and output slices must be of the same length.");
		assert_eq!(input.len() % 8, 0, "Input and output slices must be of a length divisible by 8.");

		//Create cursors for the two slices, and pass it off to the stream cipher handler
		let mut input_reader = Cursor::new(input);
		let mut ouput_writer = Cursor::new(output);

		self.cipher_stream::<B, Cursor<&[u8]>, Cursor<&mut [u8]>>(&mut input_reader, &mut ouput_writer, encipher).unwrap()
		/*
		let mut input_buf = [0 as u32; 2];
		let mut output_buf = [0 as u32; 2];

		for _ in 0..iterations {
			input_buf[0] = input_reader.read_u32::<T>().unwrap();
			input_buf[1] = input_reader.read_u32::<T>().unwrap();

			if encipher {
				self.encipher(&input_buf, &mut output_buf);
			} else {
				self.decipher(&input_buf, &mut output_buf);
			}

			ouput_writer.write_u32::<T>(output_buf[0]).unwrap();
			ouput_writer.write_u32::<T>(output_buf[1]).unwrap();
		}
		*/
	}

	/// Enciphers the given input stream into the given output stream.
	///
	/// Uses the given [ByteOrder](https://docs.rs/byteorder) passed as a template for properly parsing the streams.
	///
	/// If you're unsure which ByteOrder to use, use `BigEndian` (BE).
	///
	/// # Returns
	///
	/// Ok(()) if there were no errors in parsing.
	///
	/// Err(_) if there was an error parsing the input stream that did NOT occour on an even read.
	/// In other words, the stream's input needs to have a length that is divisible by 8.
	///
	/// **NOTE**: Unlike std::io::{Read, Write} in the case of an Err(_), the output stream IS modified
	#[inline]
	pub fn encipher_stream<B: ByteOrder, T: Read, S: Write>(&self, input: &mut T, output: &mut S) -> Result<()> {
		self.cipher_stream::<B, T, S>(input, output, true)
	}

	/// Deciphers the given input stream into the given output stream.
	///
	/// Uses the given [ByteOrder](https://docs.rs/byteorder) passed as a template for properly parsing the streams.
	///
	/// If you're unsure which ByteOrder to use, use `BigEndian` (BE).
	///
	/// # Returns
	///
	/// Ok(()) if there were no errors in parsing.
	///
	/// Err(_) if there was an error parsing the input stream that did NOT occour on an even read.
	/// In other words, the stream's input needs to have a length that is divisible by 8.
	///
	/// **NOTE**: Unlike std::io::{Read, Write} in the case of an Err(_), the output stream IS modified
	#[inline]
	pub fn decipher_stream<B: ByteOrder, T: Read, S: Write>(&self, input: &mut T, output: &mut S) -> Result<()> {
		self.cipher_stream::<B, T, S>(input, output, false)
	}

	#[inline]
	fn cipher_stream<B: ByteOrder, T: Read, S: Write>(&self, input: &mut T, output: &mut S, encipher: bool) -> Result<()> {
		let mut input_buf = [0 as u32; 2];
		let mut output_buf = [0 as u32; 2];

		loop {

			//An error parsing the first value means we should stop parsing, not fail
			input_buf[0] = match input.read_u32::<B>() {
				Ok(val) => val,
				Err(_) => break
			};
			input_buf[1] = input.read_u32::<B>()?;

			if encipher {
				self.encipher(&input_buf, &mut output_buf);
			} else {
				self.decipher(&input_buf, &mut output_buf);
			}

			output.write_u32::<B>(output_buf[0])?;
			output.write_u32::<B>(output_buf[1])?;
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use byteorder::BE;
	use std::str;
	use super::XTEA;

	#[test]
	fn overflow() {
		let xtea = XTEA::new([0xffffffff; 4]);
		let input = [1234u32, 5678u32];

		let encrypted = {
			let mut output = [0u32; 2];
			xtea.encipher(&input, &mut output);
			output
		};
		let decrypted = {
			let mut output = [0u32; 2];
			xtea.decipher(&encrypted, &mut output);
			output
		};
		assert_eq!(input, decrypted);
	}

	#[test]
	fn u8_slice() {
		let input = b"Hello. Performing a test here.00";

		let xtea = XTEA::new([0x1380C5B5, 0x28037DF9, 0x26E314A2, 0xC57684E4]);

		let encrypted = {
			let mut output = [0; 32];
			xtea.encipher_u8slice::<BE>(input, &mut output);
			output
		};

		let decrypted = {
			let mut output = [0; 32];
			xtea.decipher_u8slice::<BE>(&encrypted, &mut output);
			output
		};
		println!("Decryted: {}", str::from_utf8(&decrypted[..]).unwrap());
		assert_eq!(input, &decrypted);
	}

	#[test]
	fn boxed_slice() {
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

		println!("Decryted: {:?}", &decrypted);
		assert_eq!(input, decrypted);
	}
}
