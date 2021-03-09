//! Deserialize AT Command strings to a Rust data structure

use core::str::FromStr;
use core::{fmt, str};

use serde::{
    de::{self, Visitor},
    Deserialize,
};

use self::enum_::VariantAccess;
use self::map::MapAccess;
use self::seq::{SeqAccess, SeqByteAccess};

mod enum_;
mod map;
mod seq;

/// Deserialization result
pub type Result<T> = core::result::Result<T, Error>;

/// Wrapper type to allow deserializing a number of chars as a char vector
///
/// Example:
/// ```
/// use heapless::{consts, String};
/// use serde_at::{from_str, Bytes, CharVec, SerializeOptions};
/// use serde_derive::Deserialize;
///
/// #[derive(Debug, Deserialize, PartialEq)]
/// struct CommandStruct {
///     id: u8,
///     vec: CharVec<consts::U7>,
///     value: i32,
/// }
///
/// let incoming: CommandStruct = from_str("+CCID: 4,IMP_MSG,-12").unwrap();
///
/// let expected = CommandStruct {
///     id: 4,
///     vec: CharVec(heapless::Vec::from_slice(&['I', 'M', 'P', '_', 'M', 'S', 'G']).unwrap()),
///     value: -12,
/// };
///
/// assert_eq!(incoming, expected);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct CharVec<T: heapless::ArrayLength<char>>(pub heapless::Vec<char, T>);

impl<T> CharVec<T>
where
    T: heapless::ArrayLength<char>,
{
    #[must_use]
    pub fn new() -> Self {
        Self(heapless::Vec::<char, T>::new())
    }

    pub fn to_string(&self) -> heapless::String<T>
    where
        T: heapless::ArrayLength<u8>,
    {
        let mut str = heapless::String::new();
        for c in self.0.iter() {
            // Ignore result here, as length of both `self.0` and `str` is `T`
            str.push(*c).ok();
        }
        str
    }
}
impl<T> Default for CharVec<T>
where
    T: heapless::ArrayLength<char>,
{
    fn default() -> Self {
        Self::new()
    }
}
impl<'de, N> Deserialize<'de> for CharVec<N>
where
    N: heapless::ArrayLength<char>,
{
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ValueVisitor<'de, N>(core::marker::PhantomData<(&'de (), char, N)>);

        impl<'de, N> de::Visitor<'de> for ValueVisitor<'de, N>
        where
            N: heapless::ArrayLength<char>,
        {
            type Value = CharVec<N>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut values = heapless::Vec::new();

                while let Some(value) = seq.next_element()? {
                    if values.push(value).is_err() {
                        return Err(<A::Error as serde::de::Error>::invalid_length(
                            values.capacity() + 1,
                            &self,
                        ));
                    }
                }

                Ok(CharVec(values))
            }
        }
        deserializer.deserialize_bytes(ValueVisitor(core::marker::PhantomData))
    }
}

/// This type represents all possible errors that can occur when deserializing AT Command strings
#[allow(clippy::pub_enum_variant_names)]
#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// EOF while parsing an object.
    EofWhileParsingObject,

    /// EOF while parsing a string.
    EofWhileParsingString,

    /// EOF while parsing an AT Command string.
    EofWhileParsingNumber,

    /// EOF while parsing an AT Command string.
    EofWhileParsingValue,

    /// Expected to parse either a `true`, `false`, or a `null`.
    ExpectedSomeIdent,

    /// Expected this character to start an AT Command string.
    ExpectedSomeValue,

    /// Invalid number.
    InvalidNumber,

    /// Invalid type
    InvalidType,

    /// Invalid unicode code point.
    InvalidUnicodeCodePoint,

    /// AT Command string has non-whitespace trailing characters after the value.
    TrailingCharacters,

    /// AT Command string has a comma after the last value in an array or map.
    TrailingComma,

    /// Error with a custom message that we had to discard.
    CustomError,

    /// Error with a custom message that was preserved.
    #[cfg(feature = "custom-error-messages")]
    CustomErrorWithMessage(heapless::String<heapless::consts::U128>),
}

pub(crate) struct Deserializer<'b> {
    slice: &'b [u8],
    index: usize,
}

impl<'a> Deserializer<'a> {
    const fn new(slice: &'a [u8]) -> Deserializer<'_> {
        Deserializer { slice, index: 0 }
    }

    fn eat_char(&mut self) {
        self.index += 1;
    }

    fn end(&mut self) -> Result<()> {
        match self.parse_whitespace() {
            Some(_) => Err(Error::TrailingCharacters),
            None => Ok(()),
        }
    }

    fn next_char(&mut self) -> Option<u8> {
        let ch = self.slice.get(self.index);

        if ch.is_some() {
            self.index += 1;
        }

        ch.cloned()
    }

    fn parse_ident(&mut self, ident: &[u8]) -> Result<()> {
        for c in ident {
            if Some(*c) != self.next_char() {
                return Err(Error::ExpectedSomeIdent);
            }
        }

        Ok(())
    }

    fn parse_str(&mut self) -> Result<&'a str> {
        let start = self.index;
        loop {
            match self.peek() {
                Some(b'"') => {
                    let end = self.index;
                    self.eat_char();
                    return str::from_utf8(&self.slice[start..end])
                        .map_err(|_e| Error::InvalidUnicodeCodePoint);
                }
                Some(_) => self.eat_char(),
                None => return Err(Error::EofWhileParsingString),
            }
        }
    }

    fn parse_bytes(&mut self) -> Result<&'a [u8]> {
        let start = self.index;
        loop {
            if let Some(c) = self.peek() {
                if (c as char).is_alphanumeric() || (c as char).is_whitespace() {
                    self.eat_char()
                } else {
                    return Err(Error::EofWhileParsingString);
                }
            } else {
                let end = self.index;
                return Ok(&self.slice[start..end]);
            }
        }
    }

    fn parse_at(&mut self) -> Result<Option<()>> {
        // If we find a '+', check if it is an AT command identifier, ending in ':'
        if let Some(b'+') = self.parse_whitespace() {
            let index = self.index;
            loop {
                match self.peek() {
                    Some(b':') => {
                        self.eat_char();
                        self.parse_whitespace().ok_or(Error::EofWhileParsingValue)?;
                        return Ok(Some(()));
                    }
                    Some(_) => {
                        self.eat_char();
                    }
                    None => {
                        // Doesn't seem to be an AT command identifier. Reset index and continue
                        self.index = index;
                        break;
                    }
                }
            }
        }
        Ok(None)
    }

    /// Consumes all the whitespace characters and returns a peek into the next character
    fn parse_whitespace(&mut self) -> Option<u8> {
        loop {
            match self.peek() {
                Some(b' ') | Some(b'\n') | Some(b'\t') | Some(b'\r') => {
                    self.eat_char();
                }
                other => {
                    return other;
                }
            }
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.slice.get(self.index).cloned()
    }
}

// NOTE(deserialize_*signed) we avoid parsing into u64 and then casting to a smaller integer, which
// is what upstream does, to avoid pulling in 64-bit compiler intrinsics, which waste a few KBs of
// Flash, when targeting non 64-bit architectures
macro_rules! deserialize_unsigned {
    ($self:ident, $visitor:ident, $uxx:ident, $visit_uxx:ident) => {{
        let peek = $self
            .parse_whitespace()
            .ok_or(Error::EofWhileParsingValue)?;

        match peek {
            b'-' => Err(Error::InvalidNumber),
            b'0' => {
                $self.eat_char();
                $visitor.$visit_uxx(0)
            }
            b'1'..=b'9' => {
                $self.eat_char();

                let mut number = (peek - b'0') as $uxx;
                loop {
                    match $self.peek() {
                        Some(c @ b'0'..=b'9') => {
                            $self.eat_char();
                            number = number
                                .checked_mul(10)
                                .ok_or(Error::InvalidNumber)?
                                .checked_add((c - b'0') as $uxx)
                                .ok_or(Error::InvalidNumber)?;
                        }
                        _ => return $visitor.$visit_uxx(number),
                    }
                }
            }
            _ => Err(Error::InvalidType),
        }
    }};
}

macro_rules! deserialize_signed {
    ($self:ident, $visitor:ident, $ixx:ident, $visit_ixx:ident) => {{
        let signed = match $self
            .parse_whitespace()
            .ok_or(Error::EofWhileParsingValue)?
        {
            b'-' => {
                $self.eat_char();
                true
            }
            _ => false,
        };

        match $self.peek().ok_or(Error::EofWhileParsingValue)? {
            b'0' => {
                $self.eat_char();
                $visitor.$visit_ixx(0)
            }
            c @ b'1'..=b'9' => {
                $self.eat_char();

                let mut number = (c - b'0') as $ixx * if signed { -1 } else { 1 };
                loop {
                    match $self.peek() {
                        Some(c @ b'0'..=b'9') => {
                            $self.eat_char();
                            number = number
                                .checked_mul(10)
                                .ok_or(Error::InvalidNumber)?
                                .checked_add((c - b'0') as $ixx * if signed { -1 } else { 1 })
                                .ok_or(Error::InvalidNumber)?;
                        }
                        _ => return $visitor.$visit_ixx(number),
                    }
                }
            }
            _ => return Err(Error::InvalidType),
        }
    }};
}

macro_rules! deserialize_fromstr {
    ($self:ident, $visitor:ident, $typ:ident, $visit_fn:ident, $pattern:expr) => {{
        let start = $self.index;
        loop {
            match $self.peek() {
                Some(c) => {
                    if $pattern.iter().find(|&&d| d == c).is_some() {
                        $self.eat_char();
                    } else {
                        let s = unsafe {
                            // already checked that it contains only ascii
                            str::from_utf8_unchecked(&$self.slice[start..$self.index])
                        };
                        let v = $typ::from_str(s).or(Err(Error::InvalidNumber))?;
                        return $visitor.$visit_fn(v);
                    }
                }
                None => return Err(Error::EofWhileParsingNumber),
            }
        }
    }};
}

impl<'a, 'de> de::Deserializer<'de> for &'a mut Deserializer<'de> {
    type Error = Error;

    /// Unsupported. Can’t parse a value without knowing its expected type.
    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unreachable!()
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let peek = self.parse_whitespace().ok_or(Error::EofWhileParsingValue)?;
        match peek {
            b't' => {
                self.eat_char();
                self.parse_ident(b"rue")?;
                visitor.visit_bool(true)
            }
            b'f' => {
                self.eat_char();
                self.parse_ident(b"alse")?;
                visitor.visit_bool(false)
            }
            _ => Err(Error::InvalidType),
        }
    }

    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        deserialize_signed!(self, visitor, i8, visit_i8)
    }

    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        deserialize_signed!(self, visitor, i16, visit_i16)
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        deserialize_signed!(self, visitor, i32, visit_i32)
    }

    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        deserialize_signed!(self, visitor, i64, visit_i64)
    }

    fn deserialize_i128<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        deserialize_signed!(self, visitor, i128, visit_i128)
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        deserialize_unsigned!(self, visitor, u8, visit_u8)
    }

    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        deserialize_unsigned!(self, visitor, u16, visit_u16)
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        deserialize_unsigned!(self, visitor, u32, visit_u32)
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        deserialize_unsigned!(self, visitor, u64, visit_u64)
    }

    fn deserialize_u128<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        deserialize_unsigned!(self, visitor, u128, visit_u128)
    }

    fn deserialize_f32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.parse_whitespace().ok_or(Error::EofWhileParsingValue)?;
        deserialize_fromstr!(self, visitor, f32, visit_f32, b"0123456789+-.eE")
    }

    fn deserialize_f64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.parse_whitespace().ok_or(Error::EofWhileParsingValue)?;
        deserialize_fromstr!(self, visitor, f64, visit_f64, b"0123456789+-.eE")
    }

    fn deserialize_char<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let peek = self.parse_whitespace().ok_or(Error::EofWhileParsingValue)?;
        self.eat_char();
        visitor.visit_char(peek as char)
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let peek = self.parse_whitespace().ok_or(Error::EofWhileParsingValue)?;

        match peek {
            b'"' => {
                self.eat_char();
                visitor.visit_borrowed_str(self.parse_str()?)
            }
            _ => {
                if (peek as char).is_alphabetic() {
                    visitor.visit_bytes(self.parse_bytes()?)
                } else {
                    Err(Error::InvalidType)
                }
            }
        }
    }

    /// Unsupported. String is not available in no-std.
    fn deserialize_string<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unreachable!()
    }

    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.parse_at()?;
        visitor.visit_seq(SeqByteAccess::new(self))
    }

    /// Unsupported
    fn deserialize_byte_buf<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unreachable!()
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        match self.parse_whitespace() {
            Some(b'+') | None => visitor.visit_none(),
            Some(_) => visitor.visit_some(self),
        }
    }

    /// Unsupported. Use a more specific deserialize_* method
    fn deserialize_unit<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unreachable!()
    }

    /// Unsupported. Use a more specific deserialize_* method
    fn deserialize_unit_struct<V>(self, _name: &'static str, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unreachable!()
    }

    fn deserialize_newtype_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.parse_at()?;
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_seq(SeqAccess::new(self))
    }

    /// Unsupported
    fn deserialize_tuple<V>(self, _len: usize, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unreachable!()
    }

    /// Unsupported
    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _len: usize,
        _visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unreachable!()
    }

    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.parse_whitespace().ok_or(Error::EofWhileParsingValue)?;
        visitor.visit_map(MapAccess::new(self))
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.parse_at()?;

        // Misuse EofWhileParsingObject here to indicate finished object in vec
        // cases. Don't start a new sequence if this is not the first, and we
        // have passed the last character in the buffer
        //
        // TODO: is there a better way of doing this?!
        if self.index == self.slice.len() && self.index > 0 {
            return Err(Error::EofWhileParsingObject);
        }
        self.deserialize_seq(visitor)
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.parse_whitespace().ok_or(Error::EofWhileParsingValue)?;
        visitor.visit_enum(VariantAccess::new(self))
    }

    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_str(visitor)
    }

    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        match self.parse_whitespace().ok_or(Error::EofWhileParsingValue)? {
            b'"' => self.deserialize_str(visitor),
            b',' | b'}' | b']' => Err(Error::ExpectedSomeValue),
            _ => loop {
                match self.peek() {
                    // The visitor is expected to be UnknownAny’s visitor, which
                    // implements visit_unit to return its unit Ok result.
                    Some(b',') | Some(b'}') | Some(b']') => break visitor.visit_unit(),
                    Some(_) => self.eat_char(),
                    None => break Err(Error::EofWhileParsingString),
                }
            },
        }
    }
}

impl de::Error for Error {
    #[cfg_attr(not(feature = "custom-error-messages"), allow(unused_variables))]
    fn custom<T>(msg: T) -> Self
    where
        T: fmt::Display,
    {
        #[cfg(not(feature = "custom-error-messages"))]
        {
            Self::CustomError
        }
        #[cfg(feature = "custom-error-messages")]
        {
            use core::fmt::Write;

            let mut string = heapless::String::new();
            write!(string, "{:.64}", msg).unwrap();
            Self::CustomErrorWithMessage(string)
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::EofWhileParsingObject => "EOF while parsing an object.",
                Self::EofWhileParsingString => "EOF while parsing a string.",
                Self::EofWhileParsingValue => "EOF while parsing an AT Command string.",
                Self::ExpectedSomeIdent => {
                    "Expected to parse either a `true`, `false`, or a \
                     `null`."
                }
                Self::ExpectedSomeValue => "Expected this character to start an AT Command string.",
                Self::InvalidNumber => "Invalid number.",
                Self::InvalidType => "Invalid type",
                Self::InvalidUnicodeCodePoint => "Invalid unicode code point.",
                Self::TrailingCharacters => {
                    "AT Command string has non-whitespace trailing characters after \
                     the \
                     value."
                }
                Self::CustomError =>
                    "AT Command string does not match deserializer\u{2019}s expected format.",
                #[cfg(feature = "custom-error-messages")]
                Self::CustomErrorWithMessage(msg) => msg.as_str(),
                _ => "Invalid AT Command string",
            }
        )
    }
}

#[cfg(any(test, feature = "std"))]
impl std::error::Error for Error {}

/// Deserializes an instance of type `T` from bytes of AT Response text
pub fn from_slice<'a, T>(v: &'a [u8]) -> Result<T>
where
    T: de::Deserialize<'a>,
{
    let mut de = Deserializer::new(v);
    let value = de::Deserialize::deserialize(&mut de)?;
    de.end()?;
    Ok(value)
}

/// Deserializes an instance of type T from a string of AT Response text
pub fn from_str<'a, T>(s: &'a str) -> Result<T>
where
    T: de::Deserialize<'a>,
{
    from_slice(s.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::CharVec;
    use heapless::{consts, String};
    use serde_derive::Deserialize;

    #[derive(Debug, Clone, Deserialize, PartialEq)]
    struct CFG {
        p1: u8,
        p2: i16,
        p3: bool,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct CFGOption {
        p1: u8,
        p2: i16,
        p3: Option<bool>,
    }

    #[derive(Clone, Debug, Deserialize, PartialEq)]
    pub struct CCID {
        pub ccid: u128,
    }

    #[derive(Clone, Debug, PartialEq, Deserialize)]
    struct Handle(pub usize);

    #[derive(Clone, Debug, PartialEq, Deserialize)]
    struct CharHandle(pub char);

    #[test]
    fn simple_struct() {
        assert_eq!(
            crate::from_str("+CFG: 2,56,false"),
            Ok(CFG {
                p1: 2,
                p2: 56,
                p3: false
            })
        );
    }

    #[test]
    fn simple_struct_optionals() {
        assert_eq!(
            crate::from_str("+CFG: 2,56"),
            Ok(CFGOption {
                p1: 2,
                p2: 56,
                p3: None
            })
        );

        assert_eq!(
            crate::from_str("+CFG: 2,56, true"),
            Ok(CFGOption {
                p1: 2,
                p2: 56,
                p3: Some(true)
            })
        );
        assert_eq!(
            crate::from_str("+CFG: 2,56,false"),
            Ok(CFGOption {
                p1: 2,
                p2: 56,
                p3: Some(false)
            })
        );
    }
    #[test]
    fn simple_string() {
        #[derive(Clone, Debug, Deserialize, PartialEq)]
        pub struct StringTest {
            pub string: String<consts::U32>,
        }

        assert_eq!(
            crate::from_str("+CCID: \"89883030000005421166\""),
            Ok(StringTest {
                string: String::from("89883030000005421166")
            })
        );
    }

    #[test]
    fn cgmi_string() {
        #[derive(Clone, Debug, Deserialize, PartialEq)]
        pub struct CGMI {
            pub id: CharVec<consts::U32>,
        }

        assert_eq!(
            crate::from_slice(b"u-blox"),
            Ok(CGMI {
                id: CharVec(heapless::Vec::from_slice(&['u', '-', 'b', 'l', 'o', 'x']).unwrap())
            })
        );
    }

    #[test]
    fn u128_test() {
        assert_eq!(
            crate::from_str("+CCID: 89883030000005421166"),
            Ok(CCID {
                ccid: 89883030000005421166
            })
        );
    }

    #[test]
    fn char_test() {
        assert_eq!(crate::from_str("+CCID: B"), Ok(CharHandle('B')));
    }

    #[test]
    fn newtype_struct() {
        assert_eq!(crate::from_str("+CCID: 15"), Ok(Handle(15)));
    }

    #[test]
    fn char_vec_struct() {
        assert_eq!(
            CharVec(heapless::Vec::<char, consts::U4>::new()),
            CharVec::new()
        );

        let res: CharVec<consts::U4> = crate::from_str("+CCID: IMP_").unwrap();
        assert_eq!(
            res,
            CharVec(heapless::Vec::from_slice(&['I', 'M', 'P', '_']).unwrap())
        );

        assert_eq!(res.to_string(), String::<consts::U4>::from("IMP_"));
    }
}
