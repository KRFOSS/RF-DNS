use crate::app::DnsState;
use crate::dns_utils::handle_dns_request;
use anyhow::Result;
use hickory_proto::op::{Message, ResponseCode};
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, trace, warn};

pub async fn run_dns_server(state: DnsState, port: u16) -> Result<()> {
    // Start UDP server only
    if let Err(e) = run_udp_server(state, port.to_string()).await {
        error!("UDP DNS server error: {}", e);
    }

    Ok(())
}

async fn run_udp_server(state: DnsState, port: String) -> Result<()> {
    let bind_addr = format!("0.0.0.0:{}", port);
    let socket = std::sync::Arc::new(UdpSocket::bind(&bind_addr).await?);
    info!("UDP DNS server running on {}", bind_addr);

    let mut buf = vec![0; 512]; // Standard DNS UDP packet size

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((size, addr)) => {
                let query_data = buf[..size].to_vec();
                let state = state.clone();
                let socket = socket.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_udp_query(query_data, addr, &socket, state).await {
                        error!("Error handling UDP query from {}: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                error!("UDP socket error: {}", e);
                break;
            }
        }
    }

    Ok(())
}

async fn handle_udp_query(
    query_data: Vec<u8>,
    addr: SocketAddr,
    socket: &std::sync::Arc<UdpSocket>,
    state: DnsState,
) -> Result<()> {
    trace!(
        "Received UDP query from {}, size: {}",
        addr,
        query_data.len()
    );

    let response = match Message::from_vec(&query_data) {
        Ok(query) => {
            debug!(
                "Parsed DNS query from {}: {:?}",
                addr,
                query.queries().first()
            );

            match handle_dns_request(query, state).await {
                Ok(response) => response,
                Err(e) => {
                    error!("Error handling DNS request from {}: {}", addr, e);
                    let mut error_response = Message::new();
                    if let Ok(original_query) = Message::from_vec(&query_data) {
                        error_response.set_id(original_query.id());
                        error_response.add_queries(original_query.queries().to_vec());
                        error_response.set_recursion_desired(original_query.recursion_desired());
                    }
                    error_response.set_message_type(hickory_proto::op::MessageType::Response);
                    error_response.set_recursion_available(true);
                    error_response.set_authoritative(false);
                    error_response.set_response_code(ResponseCode::ServFail);
                    error_response
                }
            }
        }
        Err(e) => {
            error!("Failed to parse DNS query from {}: {}", addr, e);
            let mut error_response = Message::new();
            error_response.set_message_type(hickory_proto::op::MessageType::Response);
            error_response.set_recursion_available(true);
            error_response.set_authoritative(false);
            error_response.set_response_code(ResponseCode::FormErr);
            error_response
        }
    };

    let response_data = response.to_vec()?;

    if response_data.len() > 512 {
        warn!(
            "Response too large for UDP ({}), truncating",
            response_data.len()
        );
        let mut truncated_response = response.clone();
        truncated_response.set_truncated(true);
        // Remove answers to make it fit
        truncated_response.insert_answers(vec![]);
        let truncated_data = truncated_response.to_vec()?;
        socket.send_to(&truncated_data, addr).await?;
    } else {
        socket.send_to(&response_data, addr).await?;
    }

    trace!(
        "Sent UDP response to {}, size: {}",
        addr,
        response_data.len()
    );
    Ok(())
}
