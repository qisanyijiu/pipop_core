use std::fmt;
use std::io;
use std::error::Error;
use std::net::AddrParseError;

/// PTP/IP protocol error types
#[derive(Debug)]
pub enum PtpIpError {
    /// IO error
    Io(io::Error),
    /// Address parsing error
    AddrParse(AddrParseError),
    /// Protocol error (doesn't conform to PTP/IP specification)
    ProtocolError(String),
    /// Error returned by device
    DeviceError { code: u32, message: String },
    /// Session error (e.g., not open, already closed)
    SessionError(String),
    /// String encoding error
    StringEncoding(std::string::FromUtf8Error),
    /// Invalid resume data for interrupted downloads
    InvalidResumeData,
    /// Download cancelled
    DownloadCancelled,
    /// Timeout error
    Timeout,
    /// Other errors
    Other(String),
}

impl fmt::Display for PtpIpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PtpIpError::Io(e) => write!(f, "IO error: {}", e),
            PtpIpError::AddrParse(e) => write!(f, "Address parsing error: {}", e),
            PtpIpError::ProtocolError(msg) => write!(f, "Protocol error: {}", msg),
            PtpIpError::DeviceError { code, message } => 
                write!(f, "Device error (0x{:04X}): {}", code, message),
            PtpIpError::SessionError(msg) => write!(f, "Session error: {}", msg),
            PtpIpError::StringEncoding(e) => write!(f, "String encoding error: {}", e),
            PtpIpError::InvalidResumeData => write!(f, "Invalid resume data"),
            PtpIpError::DownloadCancelled => write!(f, "Download cancelled"),
            PtpIpError::Timeout => write!(f, "Operation timed out"),
            PtpIpError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl Error for PtpIpError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            PtpIpError::Io(e) => Some(e),
            PtpIpError::AddrParse(e) => Some(e),
            PtpIpError::StringEncoding(e) => Some(e),
            _ => None,
        }
    }
}

// Error conversion implementations
impl From<io::Error> for PtpIpError {
    fn from(err: io::Error) -> Self {
        if err.kind() == io::ErrorKind::TimedOut {
            PtpIpError::Timeout
        } else {
            PtpIpError::Io(err)
        }
    }
}

impl From<AddrParseError> for PtpIpError {
    fn from(err: AddrParseError) -> Self {
        PtpIpError::AddrParse(err)
    }
}

impl From<std::string::FromUtf8Error> for PtpIpError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        PtpIpError::StringEncoding(err)
    }
}

/// Result type alias
pub type Result<T> = std::result::Result<T, PtpIpError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::net::AddrParseError;

    #[test]
    fn test_ptp_ip_error_display() {
        let io_err = io::Error::new(io::ErrorKind::Other, "IO test");
        let err = PtpIpError::Io(io_err);
        assert!(format!("{}", err).starts_with("IO error: "));

        let addr_err = "invalid_ip".parse::<std::net::Ipv4Addr>().unwrap_err();
        let err = PtpIpError::AddrParse(addr_err);
        assert!(format!("{}", err).starts_with("Address parsing error: "));

        let err = PtpIpError::ProtocolError("test protocol error".to_string());
        assert_eq!(format!("{}", err), "Protocol error: test protocol error");

        let err = PtpIpError::DeviceError {
            code: 0x1234,
            message: "device error".to_string()
        };
        assert_eq!(format!("{}", err), "Device error (0x1234): device error");

        let err = PtpIpError::SessionError("session error".to_string());
        assert_eq!(format!("{}", err), "Session error: session error");

        let str_err = String::from_utf8(vec![0xFF]).unwrap_err();
        let err = PtpIpError::StringEncoding(str_err);
        assert!(format!("{}", err).starts_with("String encoding error: "));

        assert_eq!(format!("{}", PtpIpError::InvalidResumeData), "Invalid resume data");
        assert_eq!(format!("{}", PtpIpError::DownloadCancelled), "Download cancelled");
        assert_eq!(format!("{}", PtpIpError::Timeout), "Operation timed out");
        assert_eq!(format!("{}", PtpIpError::Other("other error".to_string())), "Error: other error");
    }

    #[test]
    fn test_ptp_ip_error_source() {
        let io_err = io::Error::new(io::ErrorKind::Other, "IO test");
        let err = PtpIpError::Io(io_err);
        assert!(err.source().is_some());

        let addr_err = "invalid".parse::<std::net::Ipv4Addr>().unwrap_err();
        let err = PtpIpError::AddrParse(addr_err);
        assert!(err.source().is_some());

        let str_err = String::from_utf8(vec![0xFF]).unwrap_err();
        let err = PtpIpError::StringEncoding(str_err);
        assert!(err.source().is_some());

        let err = PtpIpError::ProtocolError("test".to_string());
        assert!(err.source().is_none());
    }

    #[test]
    fn test_from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::TimedOut, "timeout");
        let err = PtpIpError::from(io_err);
        assert!(matches!(err, PtpIpError::Timeout));

        let io_err = io::Error::new(io::ErrorKind::Other, "other");
        let err = PtpIpError::from(io_err);
        assert!(matches!(err, PtpIpError::Io(_)));
    }

    #[test]
    fn test_from_addr_parse_error() {
        let addr_err = "invalid".parse::<std::net::Ipv4Addr>().unwrap_err();
        let err = PtpIpError::from(addr_err);
        assert!(matches!(err, PtpIpError::AddrParse(_)));
    }

    #[test]
    fn test_from_string_encoding_error() {
        let str_err = String::from_utf8(vec![0xFF]).unwrap_err();
        let err = PtpIpError::from(str_err);
        assert!(matches!(err, PtpIpError::StringEncoding(_)));
    }
}
