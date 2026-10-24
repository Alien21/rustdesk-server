use hbb_common::{
    bail,
    protobuf::Message,
    rendezvous_proto::{rendezvous_message::Union, KeyExchange, KxParams, RendezvousMessage},
    sodiumoxide::crypto::{box_, sign},
    tcp::{Encrypt, KxTranscript, KX_PARAMS_DOMAIN},
    ResultType,
};

pub(crate) struct KeyExchangeOffer {
    public: box_::PublicKey,
    secret: box_::SecretKey,
}

pub(crate) fn check_message(bytes: &[u8], secured: bool) -> ResultType<()> {
    match RendezvousMessage::parse_from_bytes(bytes)?.union {
        Some(Union::KeyExchange(_)) => bail!("Repeated rendezvous key exchange"),
        Some(Union::PunchHoleRequest(request)) if !secured
            && (!request.token.is_empty() || !request.switch_code.is_empty()) => {
                bail!("Rendezvous credentials require KX v1");
            }
        Some(Union::RequestRelay(request)) if !secured
            && (!request.token.is_empty() || !request.switch_code.is_empty()) => {
                bail!("Rendezvous credentials require KX v1");
            }
        _ => Ok(()),
    }
}

impl KeyExchangeOffer {
    pub(crate) fn new(signing_key: &sign::SecretKey) -> ResultType<(Self, RendezvousMessage)> {
        let (mut public, secret) = box_::gen_keypair();
        // X25519 ignores this bit; clients use its signed value to require signed parameters.
        public.0[31] |= 0x80;
        let params = KxParams {
            pk: public.0.to_vec().into(),
            version: 1,
            ..Default::default()
        };
        let mut signed = KX_PARAMS_DOMAIN.to_vec();
        signed.extend_from_slice(&params.write_to_bytes()?);
        let mut message = RendezvousMessage::new();
        message.set_key_exchange(KeyExchange {
            keys: vec![sign::sign(&public.0, signing_key).into()],
            version: 1,
            signed_params: sign::sign(&signed, signing_key).into(),
            ..Default::default()
        });
        Ok((Self { public, secret }, message))
    }

    pub(crate) fn finish(self, reply: &KeyExchange) -> ResultType<Encrypt> {
        if reply.version != 1 || reply.keys.len() != 2 || !reply.signed_params.is_empty() {
            bail!("Invalid rendezvous key exchange response");
        }
        let key = Encrypt::decode(&reply.keys[1], &reply.keys[0], &self.secret)?;
        Encrypt::new_split(key, false, &KxTranscript {
            initiator_pk: &reply.keys[0],
            responder_pk: &self.public.0,
            advertised: 1,
            picked: 1,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::{
        bytes::BytesMut,
        rendezvous_proto::{PunchHoleRequest, RequestRelay},
        sodiumoxide::crypto::secretbox,
    };

    #[test]
    fn signed_v1_exchange_delivers_authenticated_data_in_both_directions() {
        let (signing_public, signing_secret) = sign::gen_keypair();
        let (offer, greeting) = KeyExchangeOffer::new(&signing_secret).unwrap();
        let ex = greeting.key_exchange();
        let public = sign::verify(&ex.keys[0], &signing_public).unwrap();
        assert_eq!(public.len(), 32);
        assert_ne!(public[31] & 0x80, 0);
        let signed = sign::verify(&ex.signed_params, &signing_public).unwrap();
        let params = KxParams::parse_from_bytes(signed.strip_prefix(KX_PARAMS_DOMAIN).unwrap()).unwrap();
        assert_eq!(params.pk.as_ref(), public.as_slice());
        assert_eq!(params.version, 1);
        let server_public = box_::PublicKey::from_slice(&public).unwrap();
        let (client_public, client_secret) = box_::gen_keypair();
        let key = secretbox::gen_key();
        let reply = KeyExchange {
            keys: vec![client_public.0.to_vec().into(), box_::seal(
                &key.0, &box_::Nonce([0; box_::NONCEBYTES]), &server_public, &client_secret,
            ).into()],
            version: 1,
            ..Default::default()
        };
        let mut server = offer.finish(&reply).unwrap();
        let mut client = Encrypt::new_split(key, true, &KxTranscript {
            initiator_pk: &client_public.0, responder_pk: &public, advertised: 1, picked: 1,
        }).unwrap();
        let sent = client.enc(b"opaque API token");
        let mut request = BytesMut::from(sent.as_slice());
        server.dec(&mut request).unwrap();
        assert_eq!(&request[..], b"opaque API token");
        let reply = server.enc(b"opaque API token");
        assert_ne!(sent, reply);
        let mut response = BytesMut::from(reply.as_slice());
        client.dec(&mut response).unwrap();
        assert_eq!(&response[..], b"opaque API token");
    }

    #[test]
    fn invalid_exchange_and_unencrypted_credentials_are_rejected() {
        let (_, secret) = sign::gen_keypair();
        for (version, keys) in [
            (0, vec![vec![0; 32].into(), vec![0; 48].into()]),
            (1, vec![]),
            (1, vec![vec![0; 31].into(), vec![0; 48].into()]),
            (1, vec![vec![0; 32].into(), vec![0; 47].into()]),
            (1, vec![vec![0; 32].into(), vec![0; 48].into()]),
        ] {
            let (offer, _) = KeyExchangeOffer::new(&secret).unwrap();
            assert!(offer.finish(&KeyExchange { version, keys, ..Default::default() }).is_err());
        }
        let mut message = RendezvousMessage::new();
        message.set_punch_hole_request(PunchHoleRequest { token: "opaque-token".into(), ..Default::default() });
        let bytes = message.write_to_bytes().unwrap();
        assert!(check_message(&bytes, false).is_err());
        assert!(check_message(&bytes, true).is_ok());
        message.set_request_relay(RequestRelay { switch_code: "secret".into(), ..Default::default() });
        assert!(check_message(&message.write_to_bytes().unwrap(), false).is_err());
        message.set_key_exchange(KeyExchange::new());
        assert!(check_message(&message.write_to_bytes().unwrap(), true).is_err());
    }
}
