use std::fmt;

#[derive(Debug)]
pub enum DnsError {
    ParseError(String),
    NetworkError(String),
    TimeoutError(String),
    ConfigurationError(String),
    TlsError(String),
    ServerError(String),
    InvalidQuery(String),
    UpstreamError(String),
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            DnsError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            DnsError::TimeoutError(msg) => write!(f, "Timeout error: {}", msg),
            DnsError::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
            DnsError::TlsError(msg) => write!(f, "TLS error: {}", msg),
            DnsError::ServerError(msg) => write!(f, "Server error: {}", msg),
            DnsError::InvalidQuery(msg) => write!(f, "Invalid query: {}", msg),
            DnsError::UpstreamError(msg) => write!(f, "Upstream error: {}", msg),
        }
    }
}

impl std::error::Error for DnsError {}

impl From<hickory_proto::ProtoError> for DnsError {
    fn from(err: hickory_proto::ProtoError) -> Self {
        DnsError::ParseError(err.to_string())
    }
}

impl From<std::io::Error> for DnsError {
    fn from(err: std::io::Error) -> Self {
        DnsError::NetworkError(err.to_string())
    }
}

impl From<tokio::time::error::Elapsed> for DnsError {
    fn from(err: tokio::time::error::Elapsed) -> Self {
        DnsError::TimeoutError(err.to_string())
    }
}

impl From<reqwest::Error> for DnsError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            DnsError::TimeoutError(err.to_string())
        } else {
            DnsError::NetworkError(err.to_string())
        }
    }
}

impl From<anyhow::Error> for DnsError {
    fn from(err: anyhow::Error) -> Self {
        DnsError::ServerError(err.to_string())
    }
}

pub type DnsResult<T> = Result<T, DnsError>;

// 에러 응답 생성 유틸리티
pub fn create_error_response(
    query_id: u16,
    queries: Vec<hickory_proto::op::Query>,
    response_code: hickory_proto::op::ResponseCode,
) -> hickory_proto::op::Message {
    let mut response = hickory_proto::op::Message::new();
    response.set_id(query_id);
    response.set_message_type(hickory_proto::op::MessageType::Response);
    response.set_recursion_desired(true);
    response.set_recursion_available(true);
    response.set_authoritative(false);
    response.set_response_code(response_code);
    response.add_queries(queries);
    response
}
