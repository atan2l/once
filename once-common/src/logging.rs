#[cfg(feature = "logging")]
pub(crate) use log::{debug, error, info, trace, warn};

#[cfg(not(feature = "logging"))]
macro_rules! trace {
    ($($arg:tt)*) => {};
}

#[cfg(not(feature = "logging"))]
macro_rules! debug {
    ($($arg:tt)*) => {};
}

#[cfg(not(feature = "logging"))]
macro_rules! info {
    ($($arg:tt)*) => {};
}

#[cfg(not(feature = "logging"))]
macro_rules! _warn {
    ($($arg:tt)*) => {};
}

#[cfg(not(feature = "logging"))]
macro_rules! error {
    ($($arg:tt)*) => {};
}

#[cfg(not(feature = "logging"))]
pub(crate) use {debug, error, info, trace, _warn as warn};