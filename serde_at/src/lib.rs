// #![deny(missing_docs)]
#![deny(rust_2018_compatibility)]
#![deny(rust_2018_idioms)]
#![deny(warnings)]
#![cfg_attr(not(feature = "std"), no_std)]

pub mod de;
pub mod ser;

#[doc(inline)]
pub use self::de::{from_slice, from_str};
#[doc(inline)]
pub use self::ser::{to_string, to_vec};

#[allow(deprecated)]
unsafe fn uninitialized<T>() -> T {
    core::mem::uninitialized()
}
