use core::fmt;

#[derive(Debug, Clone)]
pub struct DnsError {
    message: String,
}

impl fmt::Display for DnsError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}", self.message)
    }
}
