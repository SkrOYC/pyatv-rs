//! Literal constructors for [`crate::Value`].
//!
//! Companion builds every message as a nested dictionary of strings, integers, booleans, byte
//! strings and sub-dictionaries (`pyatv/protocols/companion/api.py:161-210`). Spelling those out
//! with [`crate::Value::dict`] needs an explicit `Value::from` per heterogeneous entry, so these
//! two macros exist purely to keep call sites readable. They add no behaviour of their own.

/// Build a [`crate::Value::Dict`] from `key => value` pairs, in the order written.
///
/// Keys and values are converted with [`From`], so anything with an `impl Into<Value>` works and
/// a nested `opack!`/`opack_array!` can be used directly.
///
/// ```
/// use pyatv_opack::{opack, opack_array, Value};
///
/// let message = opack! {
///     "_i" => "_systemInfo",
///     "_t" => 2u64,
///     "_c" => opack! {
///         "_bf" => 0u64,
///         "_stA" => opack_array!["com.apple.LiveAudio", "com.apple.Seymour"],
///         "_btHP" => false,
///     },
/// };
///
/// assert_eq!(message.get("_i").and_then(Value::as_str), Some("_systemInfo"));
/// assert_eq!(opack!(), Value::Dict(Vec::new()));
/// ```
#[macro_export]
macro_rules! opack {
    () => {
        $crate::Value::Dict(::std::vec::Vec::new())
    };
    ($($key:expr => $value:expr),+ $(,)?) => {
        $crate::Value::Dict(::std::vec![
            $(($crate::Value::from($key), $crate::Value::from($value))),+
        ])
    };
}

/// Build a [`crate::Value::Array`] from a comma-separated list, converting each element with
/// [`From`].
///
/// Unlike [`crate::Value::array`] the elements need not share a type.
///
/// ```
/// use pyatv_opack::{opack_array, Value};
///
/// assert_eq!(
///     opack_array![1u64, "two", false],
///     Value::Array(vec![Value::Uint(1), Value::from("two"), Value::Bool(false)]),
/// );
/// assert_eq!(opack_array![], Value::Array(Vec::new()));
/// ```
#[macro_export]
macro_rules! opack_array {
    ($($value:expr),* $(,)?) => {
        $crate::Value::Array(::std::vec![$($crate::Value::from($value)),*])
    };
}
