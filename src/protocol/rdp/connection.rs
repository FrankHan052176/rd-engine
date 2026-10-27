//! Minimal adaptation of ironrdp-async/src/{connector,framed}.rs at
//! 11a0810cfbbabd8b8023875a05e3041216d4b01b; see LICENSE-IRONRDP-MIT.
//!
//! The stock finalize helper consumes and discards the server Input capability.
//! Drive the same upstream sequences, observing DemandActive through upstream
//! decoders before it is consumed. No local PDU, CredSSP or network codec lives
//! here. Initial-connection cancellation still drops the entire owned socket.

use ironrdp_connector::connection_activation::ConnectionActivationState;
use ironrdp_connector::credssp::CredsspSequence;
use ironrdp_connector::sspi::generator::GeneratorState;
use ironrdp_connector::{ClientConnector, ClientConnectorState, ConnectionResult, Credentials, Sequence, ServerName, Written};
use ironrdp_core::WriteBuf;
use ironrdp_pdu::rdp::capability_sets::{CapabilitySet, InputFlags};
use ironrdp_pdu::rdp::headers::ShareControlPdu;
use ironrdp_tokio::reqwest::ReqwestNetworkClient;
use ironrdp_tokio::{FramedWrite as _, NetworkClient as _, TokioFramed, Upgraded};
use zeroize::Zeroize as _;

use super::{RdpError, connector_error, tls, transport_error};

/// Owns the public connector credentials from construction through finalization.
/// Drop also scrubs them when a connection attempt errors or is cancelled.
pub(super) struct ConnectorGuard(pub(super) ClientConnector);

impl ConnectorGuard {
    fn clear_password(&mut self) {
        match &mut self.0.config.credentials {
            Credentials::UsernamePassword { password, .. } => password.zeroize(),
            Credentials::SmartCard { pin, .. } => pin.zeroize(),
        }
    }
}

impl Drop for ConnectorGuard {
    fn drop(&mut self) {
        self.clear_password();
    }
}

pub(super) async fn finalize(
    _upgraded: Upgraded,
    mut connector: ConnectorGuard,
    framed: &mut TokioFramed<tls::TlsStream>,
    network: &mut ReqwestNetworkClient,
    server_name: ServerName,
    public_key: Vec<u8>,
) -> Result<(ConnectionResult, InputFlags), RdpError> {
    let mut buffer = WriteBuf::new();
    if !connector.0.should_perform_credssp() {
        return Err(RdpError::Protocol("NLA was not negotiated"));
    }
    authenticate(&mut connector.0, framed, network, &mut buffer, server_name, public_key).await?;

    let mut input_flags = InputFlags::empty();
    loop {
        let observe_input = match &connector.0.state {
            ClientConnectorState::CapabilitiesExchange { connection_activation } => {
                matches!(connection_activation.connection_activation_state(), ConnectionActivationState::CapabilitiesExchange)
            }
            _ => false,
        };
        let encoding_client_info = matches!(connector.0.state, ClientConnectorState::SecureSettingsExchange { .. });
        let written = step_read(
            framed, &mut connector.0, &mut buffer,
            observe_input.then_some(&mut input_flags),
        ).await?;
        if encoding_client_info {
            // SecureSettingsExchange has encoded ClientInfo into `buffer`.
            // The password is no longer needed by Config; wipe it before any
            // write await or the subsequent activation/factory Config clones.
            // Licensing still needs the username and domain, so retain those.
            connector.clear_password();
        }
        if let Some(size) = written.size() {
            framed.write_all(&buffer.filled()[..size]).await.map_err(transport_error)?;
        }
        if encoding_client_info {
            // That ClientInfo PDU carries the password verbatim, protected only
            // by the TLS channel. Drop the encoded copy together with the buffer
            // that holds it; the loop keeps reusing a fresh one.
            buffer.into_inner().zeroize();
            buffer = WriteBuf::new();
        }
        if matches!(connector.0.state, ClientConnectorState::Connected { .. }) {
            return match std::mem::take(&mut connector.0.state) {
                ClientConnectorState::Connected { result } => Ok((result, input_flags)),
                _ => Err(RdpError::Protocol("invalid finalized connector state")),
            };
        }
    }
}

/// Same cancellation-safe read/step ordering as upstream single_sequence_step_read.
/// On return the caller must retain the output before awaiting its write. Passing
/// a flags slot is only valid during the DemandActive capability-exchange phase.
pub(super) async fn step_read(
    framed: &mut TokioFramed<tls::TlsStream>,
    sequence: &mut dyn Sequence,
    buffer: &mut WriteBuf,
    input_flags: Option<&mut InputFlags>,
) -> Result<Written, RdpError> {
    buffer.clear();
    if let Some(hint) = sequence.next_pdu_hint() {
        let pdu = framed.read_by_hint(hint).await.map_err(transport_error)?;
        let server_flags = if input_flags.is_some() {
            demand_active_input_flags(&pdu)?
        } else {
            None
        };
        let written = sequence.step(&pdu, buffer).map_err(connector_error)?;
        if let (Some(flags), Some(server_flags)) = (input_flags, server_flags) {
            *flags = server_flags;
        }
        Ok(written)
    } else {
        sequence.step_no_input(buffer).map_err(connector_error)
    }
}

fn demand_active_input_flags(pdu: &[u8]) -> Result<Option<InputFlags>, RdpError> {
    let data = ironrdp_pdu::mcs::decode_send_data_indication(pdu)
        .map_err(|_| RdpError::Protocol("DemandActive MCS decode"))?;
    let control = ironrdp_pdu::rdp::headers::decode_share_control(data)
        .map_err(|_| RdpError::Protocol("DemandActive share control decode"))?;
    match control.pdu {
        ShareControlPdu::ServerDemandActive(active) => {
            let flags = active.pdu.capability_sets.into_iter().find_map(|capability| {
                match capability {
                    CapabilitySet::Input(input) => Some(input.input_flags),
                    _ => None,
                }
            }).unwrap_or_else(InputFlags::empty);
            Ok(Some(flags))
        }
        // The upstream activation sequence permits repeated DeactivateAll
        // before DemandActive. It validates every other unexpected PDU itself.
        _ => Ok(None),
    }
}

async fn authenticate(
    connector: &mut ClientConnector,
    framed: &mut TokioFramed<tls::TlsStream>,
    network: &mut ReqwestNetworkClient,
    buffer: &mut WriteBuf,
    server_name: ServerName,
    public_key: Vec<u8>,
) -> Result<(), RdpError> {
    let selected_protocol = match connector.state {
        ClientConnectorState::Credssp { selected_protocol } => selected_protocol,
        _ => return Err(RdpError::Protocol("invalid CredSSP state")),
    };
    let (mut sequence, mut request) = CredsspSequence::init(
        connector.config.credentials.clone(),
        connector.config.domain.as_deref(),
        selected_protocol,
        server_name,
        public_key,
        None,
    ).map_err(connector_error)?;
    loop {
        let client_state = {
            let mut generator = sequence.process_ts_request(request);
            let mut state = generator.start();
            loop {
                state = match state {
                    GeneratorState::Suspended(request) => {
                        let response = network.send(&request).await.map_err(connector_error)?;
                        generator.resume(Ok(response))
                    }
                    GeneratorState::Completed(result) => {
                        break result.map_err(|_| RdpError::Authentication)?;
                    }
                };
            }
        };
        buffer.clear();
        let written = sequence.handle_process_result(client_state, buffer).map_err(connector_error)?;
        if let Some(size) = written.size() {
            framed.write_all(&buffer.filled()[..size]).await.map_err(transport_error)?;
        }
        let Some(hint) = sequence.next_pdu_hint() else {
            break;
        };
        let pdu = framed.read_by_hint(hint).await.map_err(transport_error)?;
        match sequence.decode_server_message(&pdu).map_err(connector_error)? {
            Some(next_request) => request = next_request,
            None => break,
        }
    }
    connector.mark_credssp_as_done();
    Ok(())
}
