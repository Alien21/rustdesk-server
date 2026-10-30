use hbb_common::{
    bail,
    bytes::BytesMut,
    protobuf::{CodedOutputStream, Message, UnknownValueRef},
    rendezvous_proto::{rendezvous_message::Union, KeyExchange, RendezvousMessage},
    sodiumoxide::crypto::{
        box_, generichash,
        secretbox::{self, Key},
        sign,
    },
    tcp,
    ResultType,
};

const KX_PARAMS_DOMAIN: &[u8] = b"rdkx-params";

#[derive(Clone)]
pub(crate) struct Encrypt {
    send: tcp::Encrypt,
    receive: tcp::Encrypt,
}

impl Encrypt {
    pub(crate) fn new_split(
        key: Key,
        is_initiator: bool,
        initiator_pk: &[u8],
        responder_pk: &[u8],
    ) -> ResultType<Self> {
        let initiator = Self::derive_subkey(&key, 1, initiator_pk, responder_pk)?;
        let responder = Self::derive_subkey(&key, 2, initiator_pk, responder_pk)?;
        let (send, receive) = if is_initiator {
            (initiator, responder)
        } else {
            (responder, initiator)
        };
        Ok(Self {
            send: tcp::Encrypt::new(send),
            receive: tcp::Encrypt::new(receive),
        })
    }

    fn derive_subkey(
        key: &Key,
        direction: u8,
        initiator_pk: &[u8],
        responder_pk: &[u8],
    ) -> ResultType<Key> {
        if initiator_pk.len() != box_::PUBLICKEYBYTES || responder_pk.len() != box_::PUBLICKEYBYTES {
            bail!("key exchange transcript has a public key of the wrong length");
        }
        let failed = |_| hbb_common::anyhow::anyhow!("key derivation failed");
        let mut h = generichash::State::new(Some(secretbox::KEYBYTES), Some(&key.0)).map_err(failed)?;
        for part in [
            b"rdkx-spl".as_slice(),
            &[direction],
            &1u32.to_le_bytes(),
            &1u32.to_le_bytes(),
            initiator_pk,
            responder_pk,
        ] {
            h.update(part).map_err(failed)?;
        }
        let mut subkey = [0u8; secretbox::KEYBYTES];
        subkey.copy_from_slice(h.finalize().map_err(failed)?.as_ref());
        Ok(Key(subkey))
    }

    pub(crate) fn enc(&mut self, data: &[u8]) -> Vec<u8> {
        self.send.enc(data)
    }

    pub(crate) fn dec(&mut self, bytes: &mut BytesMut) -> std::io::Result<()> {
        self.receive.dec(bytes)
    }
}

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
        let mut signed = KX_PARAMS_DOMAIN.to_vec();
        {
            let mut params = CodedOutputStream::vec(&mut signed);
            params.write_bytes(1, &public.0)?;
            params.write_uint32(2, 1)?;
            params.flush()?;
        }
        let mut message = RendezvousMessage::new();
        let mut exchange = KeyExchange {
            keys: vec![sign::sign(&public.0, signing_key).into()],
            ..Default::default()
        };
        // Keep the upstream schema intact while carrying its newer KX fields on the wire.
        let fields = exchange.special_fields.mut_unknown_fields();
        fields.add_varint(2, 1);
        fields.add_length_delimited(3, sign::sign(&signed, signing_key));
        message.set_key_exchange(exchange);
        Ok((Self { public, secret }, message))
    }

    pub(crate) fn finish(self, reply: &KeyExchange) -> ResultType<Encrypt> {
        let fields = reply.special_fields.unknown_fields();
        let signed_params_empty = match fields.get(3) {
            None => true,
            Some(UnknownValueRef::LengthDelimited(value)) => value.is_empty(),
            _ => false,
        };
        if fields.get(2) != Some(UnknownValueRef::Varint(1))
            || reply.keys.len() != 2
            || !signed_params_empty
        {
            bail!("Invalid rendezvous key exchange response");
        }
        let key = tcp::Encrypt::decode(&reply.keys[1], &reply.keys[0], &self.secret)?;
        Encrypt::new_split(key, false, &reply.keys[0], &self.public.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::rendezvous_proto::{PunchHoleRequest, RequestRelay};

    #[test]
    fn signed_v1_exchange_delivers_authenticated_data_in_both_directions() {
        let (signing_public, signing_secret) = sign::gen_keypair();
        let (offer, greeting) = KeyExchangeOffer::new(&signing_secret).unwrap();
        let ex = greeting.key_exchange();
        let public = sign::verify(&ex.keys[0], &signing_public).unwrap();
        assert_eq!(public.len(), 32);
        assert_ne!(public[31] & 0x80, 0);
        assert_eq!(ex.special_fields.unknown_fields().get(2), Some(UnknownValueRef::Varint(1)));
        let Some(UnknownValueRef::LengthDelimited(signed)) = ex.special_fields.unknown_fields().get(3) else {
            panic!("missing signed KX parameters");
        };
        let signed = sign::verify(signed, &signing_public).unwrap();
        let mut expected = vec![0x0a, 32];
        expected.extend_from_slice(&public);
        expected.extend_from_slice(&[0x10, 1]);
        assert_eq!(signed.strip_prefix(KX_PARAMS_DOMAIN).unwrap(), expected);
        let server_public = box_::PublicKey::from_slice(&public).unwrap();
        let (client_public, client_secret) = box_::gen_keypair();
        let key = secretbox::gen_key();
        let mut reply = KeyExchange {
            keys: vec![client_public.0.to_vec().into(), box_::seal(
                &key.0, &box_::Nonce([0; box_::NONCEBYTES]), &server_public, &client_secret,
            ).into()],
            ..Default::default()
        };
        reply.special_fields.mut_unknown_fields().add_varint(2, 1);
        let mut server = offer.finish(&reply).unwrap();
        let mut client = Encrypt::new_split(key, true, &client_public.0, &public).unwrap();
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
    fn v1_matches_client_wire_vectors() {
        let client = Encrypt::new_split(Key([0x11; 32]), true, &[0x22; 32], &[0x33; 32]).unwrap();
        let hex = |value: &[u8]| value.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        assert_eq!(hex(&client.send.0.0), "c189ec6e1935c0751cfc85a0f075405cae507d7925bb19687caf56cbb54e0ecf");
        assert_eq!(hex(&client.receive.0.0), "8a62648e9195cb10ea900c0a24d2a166c1e982347a2dc6833c3e756bf5715d36");
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
            let mut reply = KeyExchange { keys, ..Default::default() };
            reply.special_fields.mut_unknown_fields().add_varint(2, version);
            assert!(offer.finish(&reply).is_err());
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
