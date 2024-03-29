use core::fmt;
use core::fmt::Debug;
use core::marker::PhantomData;
use core::ops::{Deref, Shl};
use serde::de::Visitor;
use serde::{de, Deserialize};

struct HexLiteralVisitor<T> {
    _ty: PhantomData<T>,
}

/// `HexStr<T>`
/// A hex string. Has fields used in serializing whether to add a 0x to the encoding
/// and to make the hex value in capital letters or not.
/// Can be dereferenced to its value.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HexStr<T> {
    /// Value of the hex string. Can be dereferenced
    pub val: T,
    /// Flag to add 0x when serializing the value
    pub add_0x_with_encoding: bool,
    /// Flag to serialize the hex in capital letters
    pub hex_in_caps: bool,
    /// Flag to split every n amount of nibbles with a delimiter
    pub delimiter_after_nibble_count: usize,
    /// Split every n amount of nibbles with this delimiter
    pub delimiter: char,
    /// Skip last 0 values. Whether or not to include 0 values
    pub skip_last_0_values: bool,
}

impl<T> Default for HexStr<T>
where
    T: Default,
{
    fn default() -> Self {
        Self {
            val: T::default(),
            add_0x_with_encoding: false,
            hex_in_caps: true,
            delimiter_after_nibble_count: 0,
            delimiter: ' ',
            skip_last_0_values: true,
        }
    }
}

macro_rules! impl_hex_literal_visitor {
    ($($int_type:ty)*) => {$(
        impl<'de> Visitor<'de> for HexLiteralVisitor<$int_type> {
            type Value = $int_type;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an unsigned integer in hexadecimal notation")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let mut s = core::str::from_utf8(v)
                    .map_err(serde::de::Error::custom)?;
                if s.starts_with("0x") || s.starts_with("0X") {
                    s = &s[2..];
                }

                let mut ret: $int_type = 0;

                for c in s.chars() {
                    let v = match c {
                        '0'..='9' => Some((c as $int_type) - ('0' as $int_type)),
                        'A'..='F' => Some(0xA + ((c as $int_type) - ('A' as $int_type))),
                        'a'..='f' => Some(0xa + ((c as $int_type) - ('a' as $int_type))),
                        _ => None
                    };

                    if let Some(v) = v {
                        ret = ret
                            .shl(4i32)
                            .checked_add(v)
                            .ok_or(serde::de::Error::custom("Invalid number"))?;
                    }
                }

                Ok(ret)
            }
        }

        impl<'de> Deserialize<'de> for HexStr<$int_type> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where
                    D: serde::Deserializer<'de>,
            {
                let val = deserializer.deserialize_bytes(HexLiteralVisitor::<$int_type> { _ty: PhantomData })?;
                Ok(HexStr { val, ..Default::default() })
            }
        }

        impl Deref for HexStr<$int_type> {
            type Target = $int_type;

            fn deref(&self) -> &Self::Target {
                &self.val
            }
        }
    )*}
}

impl_hex_literal_visitor! { u8 u16 u32 u64 u128 }

#[cfg(feature = "hex_str_arrays")]
mod unstable {
    use crate::de::hex_str::HexLiteralVisitor;
    use crate::HexStr;
    use core::fmt;
    use core::marker::PhantomData;
    use core::ops::Deref;
    use serde::de::Visitor;
    use serde::{de, Deserialize};

    impl<'de, const N: usize> Visitor<'de> for HexLiteralVisitor<[u8; N]> {
        type Value = [u8; N];

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a byte string written in")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let mut s = core::str::from_utf8(v).map_err(serde::de::Error::custom)?;
            if s.starts_with("0x") || s.starts_with("0X") {
                s = &s[2..];
            }

            let mut ret: [u8; N] = [0; N];
            let mut current = 0u8;
            let mut index = 0usize;
            let mut nibble_count = 0;

            for c in s.chars() {
                let v = match c {
                    '0'..='9' => Some((c as u8) - (b'0')),
                    'A'..='F' => Some(0xA + ((c as u8) - (b'A'))),
                    'a'..='f' => Some(0xa + ((c as u8) - (b'a'))),
                    _ => None,
                };

                if let Some(v) = v {
                    if nibble_count == 1 {
                        ret[index] = (current << 4) + v;
                        current = 0;
                        nibble_count = 0;
                        index += 1;
                    } else {
                        current = v;
                        nibble_count = 1;
                    }
                }
            }

            if nibble_count == 1 {
                ret[index] = current;
            }

            Ok(ret)
        }
    }

    impl<'de, const N: usize> Deserialize<'de> for HexStr<[u8; N]> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let val: [u8; N] = deserializer
                .deserialize_bytes(HexLiteralVisitor::<[u8; N]> { _ty: PhantomData })?;
            Ok(HexStr {
                val,
                add_0x_with_encoding: false,
                hex_in_caps: true,
                delimiter_after_nibble_count: 0,
                delimiter: ' ',
                skip_last_0_values: false,
            })
        }
    }

    impl<const N: usize> Deref for HexStr<[u8; N]> {
        type Target = [u8; N];

        fn deref(&self) -> &Self::Target {
            &self.val
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::de::hex_str::HexStr;

    #[test]
    pub fn test_parsing_a_hex_string() {
        let val: HexStr<u8> = crate::from_str("+CCID: 0x8d").unwrap();
        assert_eq!(*val, 0x8d);
        let val: HexStr<u8> = crate::from_str("+CCID: 8:d").unwrap();
        assert_eq!(*val, 0x8d);
        let val: HexStr<u16> = crate::from_str("+CCID: 0x0B00").unwrap();
        assert_eq!(*val, 0x0B00);
        let val: HexStr<u32> = crate::from_str("+CCID: D3AdB3ef").unwrap();
        assert_eq!(*val, 0xd3adb3ef);
        let val: HexStr<u64> = crate::from_str("+CCID: 0xFeedfACECAfeBE3F").unwrap();
        assert_eq!(*val, 0xFeedfACECAfeBE3F);
        let val: HexStr<u64> = crate::from_str("+CCID: 0xFee-dfA-CE-C-Afe-BE-3F").unwrap();
        assert_eq!(*val, 0xFeedfACECAfeBE3F);
        let val: HexStr<u128> =
            crate::from_str("+CCID: 0x1234567890abcdef1234567890abcdef").unwrap();
        assert_eq!(*val, 0x1234567890abcdef1234567890abcdef);
        let val: HexStr<u128> =
            crate::from_str("+CCID: 0x12:34:56:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef").unwrap();
        assert_eq!(*val, 0x1234567890abcdef1234567890abcdef);
    }

    #[cfg(feature = "hex_str_arrays")]
    #[test]
    pub fn test_hex_str_arrays() {
        let val: HexStr<[u8; 16]> =
            crate::from_str("+CCID: 0x12:34:56:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef").unwrap();
        assert_eq!(
            *val,
            [
                0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
                0xcd, 0xef
            ]
        );
    }
}
