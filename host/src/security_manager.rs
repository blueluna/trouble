#![warn(missing_docs)]

use rand_core::{CryptoRng, RngCore};

use crate::{
    crypto::{Nonce, PublicKey, SecretKey},
    Error,
};

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum SecurityManagerError {
    PasskeyEntryFailed = 1,
    OobNotAvailable,
    AuthenticationRequirements,
    ConfirmValueFailed,
    PairingNotSupported,
    EncryptionKeySize,
    CommandNotSupported,
    UnspecifiedReason,
    RepeatedAttempts,
    InvalidParameters,
    DHKeyCheckFailed,
    NumericComparisonFailed,
    BrEdrPairingInProgress,
    GenerationNotAllowed,
    KeyRejected,
}

/// Device I/O capabilities
// ([Vol 3] Part H, Section 2.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum IoCapabilities {
    /// Display only
    DisplayOnly = 0,
    /// Yes/no display
    DisplayYesNo = 1,
    /// Keyboard only
    KeyboardOnly = 2,
    /// No input and no output
    NoInputNoOutput = 3,
    /// Both keyboard and display
    KeyboardDisplay = 4,
}

/// Out of band (OOB) authentication data
// ([Vol 3] Part H, Section 2.3.3).
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum OobDataFlag {
    /// OOB not present
    NotPresent = 0,
    /// OOB present
    Present = 1,
}

/// Bit field indicating the type of bonding requested
// ([Vol 3] Part H, Section 3.5.1).
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum BondingFlag {
    /// No bonding
    NoBonding = 0,
    /// Bonding
    Bonding = 1,
}

/// AuthReq octet
// ([Vol 3] Part H, Section 3.5.1).
pub struct AuthReq(u8);

/// Man in the middle (MITM) protection requested
const AUTH_REQ_MITM: u8 = 0b0000_0100;
/// LE Secure Connections supported
const AUTH_REQ_SECURE_CONNECTION: u8 = 0b0000_1000;
/// Keypress notification during Passkey entry protocol
const AUTH_REQ_KEY_PRESS: u8 = 0b0001_0000;
/// Support for the h7 function
const AUTH_REQ_CT2: u8 = 0b0010_0000;

impl AuthReq {
    /// Build a AuthReq octet
    pub fn new(bonding: BondingFlag) -> Self {
        AuthReq((bonding as u8) | AUTH_REQ_MITM | AUTH_REQ_SECURE_CONNECTION | AUTH_REQ_CT2)
    }
    /// Man in the middle (MITM) protection requested
    pub fn man_in_the_middle(&self) -> bool {
        self.0 | AUTH_REQ_MITM == AUTH_REQ_MITM
    }
    /// LE Secure Connections supported
    pub fn secure_connection(&self) -> bool {
        self.0 | AUTH_REQ_SECURE_CONNECTION == AUTH_REQ_SECURE_CONNECTION
    }
    ///  Keypress notification during Passkey entry protocol
    pub fn key_press_notification(&self) -> bool {
        self.0 | AUTH_REQ_KEY_PRESS == AUTH_REQ_KEY_PRESS
    }
    /// Support for the h7 function
    pub fn ct2(&self) -> bool {
        self.0 | AUTH_REQ_CT2 == AUTH_REQ_CT2
    }
}

impl From<u8> for AuthReq {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<AuthReq> for u8 {
    fn from(value: AuthReq) -> u8 {
        value.0
    }
}

/// Security Manager Pairing Request
// ([Vol 3] Part H, Section 3.5.1).
const SM_PAIRING_REQUEST: u8 = 0x01;
/// Security Manager Pairing Response
// ([Vol 3] Part H, Section 3.5.2).
const SM_PAIRING_RESPONSE: u8 = 0x02;
/// Security Manager Pairing Confirm
// ([Vol 3] Part H, Section 3.5.3).
const SM_PAIRING_CONFIRM: u8 = 0x03;
/// Security Manager Pairing Random
// ([Vol 3] Part H, Section 3.5.4).
const SM_PAIRING_RANDOM: u8 = 0x04;
/// Security Manager Pairing Failed
// ([Vol 3] Part H, Section 3.5.5).
const SM_PAIRING_FAILED: u8 = 0x05;
/// Security Manager Pairing Public Key
// ([Vol 3] Part H, Section 3.5.6).
const SM_PAIRING_PUBLIC_KEY: u8 = 0x0c;
/// Security Manager Pairing DH key check
// ([Vol 3] Part H, Section 3.5.7).
const SM_PAIRING_DHKEY_CHECK: u8 = 0x0d;
/// Security Manager Key Press Notification
// ([Vol 3] Part H, Section 3.5.8).
const SM_PAIRING_KEY_PRESS: u8 = 0x0e;

/// Security manager that handles SM packet
pub struct SecurityManager<'r, R> {
    rng: &'r mut R,
}

impl<'r, R: RngCore + CryptoRng> SecurityManager<'r, R> {
    pub(crate) fn new(rng: &'r mut R) -> Self {
        Self { rng }
    }
    /// Handle packet
    pub(crate) fn handle(&self, src_handle: u16, payload: &[u8]) -> Result<(), Error> {
        let data = &payload[1..];
        let command = payload[0];

        match command {
            SM_PAIRING_REQUEST => self.handle_pairing_request(src_handle, data),
            SM_PAIRING_PUBLIC_KEY => self.handle_pairing_public_key(src_handle, data),
            SM_PAIRING_RANDOM => self.handle_pairing_random(src_handle, data),
            SM_PAIRING_DHKEY_CHECK => {
                todo!()
            }
            _ => {
                // handle FAILURE
                error!("Unknown SM command {}", command);
                todo!()
            }
        }
    }

    /*
    fn encode_sm_data<'a>(&self, data: &[u8], target: &'a mut [u8]) -> &'a [u8] {
        target.copy_from_slice(&[
            0x0, 0x0, // len set later
            0x6, 0x0, // channel
        ]);
        target[4..data.len() + 4].copy_from_slice(data);
        let len = data.len() - 4;
        target[0] = (len & 0xff) as u8;
        target[1] = ((len >> 8) & 0xff) as u8;
        &target[..data.len() + 4]
    }

    async fn write_sm_data(&self, handle: u16, data: &[u8]) -> Result<(), BleHostError<C::Error>> {
        let mut sm_data_buf = [0u8; 256];
        let encoded_data = self.encode_sm_data(data, &mut sm_data_buf);

        let packet = AclPacket::new(
            ConnHandle::new(handle),
            AclPacketBoundary::FirstNonFlushable,
            AclBroadcastFlag::PointToPoint,
            encoded_data,
        );
        self.controller
            .write_acl_data(&packet)
            .await
            .map_err(|e| BleHostError::Controller(e))
    }
    */

    fn handle_pairing_request(&self, src_handle: u16, data: &[u8]) -> Result<(), Error> {
        // TODO: save A/O/I
        if data.len() >= 3 {
            let auth_req = data[2];
            let oob_data = data[1] != 0;
            let io_cap = data[0];
        }

        if data.len() >= 7 {
            debug!(
                "[security manager] Request {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                data[0], data[1], data[2], data[3], data[4], data[5], data[6]
            );
        }

        /// Maximum encryption key size in octets, 128-bits
        const MAX_ENC_KEY_SIZE: u8 = 0x10;
        // const KEY_DISTRIBUTION_

        let req_data = [
            SM_PAIRING_RESPONSE,
            IoCapabilities::DisplayYesNo as u8,
            OobDataFlag::NotPresent as u8,
            AuthReq::new(BondingFlag::Bonding).into(),
            MAX_ENC_KEY_SIZE,
            0,
            0,
        ];
        Ok(())
        // self.write_sm_data(src_handle, &req_data).await
    }

    fn handle_pairing_public_key(&self, src_handle: u16, pka: &[u8]) -> Result<(), Error> {
        debug!("[security manager] Handle pairing public key");
        debug!("[security manager] key len = {} {:02x?}", pka.len(), pka);
        let pka = PublicKey::from_bytes(pka);

        // Send the local public key before validating the remote key to allow
        // parallel computation of DHKey. No security risk in doing so.

        // let skb = SecretKey::new(self.rng);
        // let pkb = skb.public_key();

        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        // x.copy_from_slice(pkb.x.as_be_bytes());
        // y.copy_from_slice(pkb.y.as_be_bytes());
        x.reverse();
        y.reverse();

        let mut data = [0u8; 65];
        data[0] = SM_PAIRING_PUBLIC_KEY;
        data[1..33].copy_from_slice(&x);
        data[33..65].copy_from_slice(&y);

        // self.write_sm_data(src_handle, &data).await?;

        // let dh_key = match skb.dh_key(pka) {
        //     Some(dh_key) => Ok(dh_key),
        //     None => Err(Error::Security(SecurityManagerError::DHKeyCheckFailed)),
        // }?;

        // SUBTLE: The order of these send/recv ops is important. See last
        // paragraph of Section 2.3.5.6.2.
        // let nb = Nonce::new(self.rng);
        // let cb = nb.f4(pkb.x(), pka.x(), 0);

        let mut data = [0u8; 17];
        data[0] = SM_PAIRING_CONFIRM;
        // data[1..17].copy_from_slice(&cb.0.to_le_bytes());

        // self.write_sm_data(src_handle, &data).await?;

        // TODO: update keys
        // self.pka = Some(pka);
        // self.pkb = Some(pkb);
        // self.skb = Some(skb);
        // self.confirm = Some(cb);
        // self.nb = Some(nb);
        // self.dh_key = Some(dh_key);

        Ok(())
    }

    fn handle_pairing_random(&self, src_handle: u16, random: &[u8]) -> Result<(), Error> {
        debug!("[security manager] Handle pairing random");
        debug!("[security manager] Got pairing random: {:02x?}", random);

        // TODO: Do checking

        // Write nb data
        let mut data = [0u8; 17];
        data[0] = SM_PAIRING_RANDOM;
        // TODO: add nb
        // data[1..17].copy_from_slice(self.nb.unwrap().0.to_le_bytes());
        // self.write_sm_data(src_handle, &data).await?;

        let na = Nonce(u128::from_le_bytes(random.try_into().unwrap()));
        // TODO: calculation
        // self.na = Some(na);
        // let nb = self.nb.unwrap();
        // let vb = na.g2(self.pka.as_ref().unwrap().x(), self.pkb.as_ref().unwrap().x(), &nb);

        // should display the code and get confirmation from user (pin ok or not) - if not okay send a pairing-failed
        // assume it's correct or the user will cancel on central
        // TODO: What is pin_callback used for?
        // info!("Display code is {}", vb.0);
        // if let Some(pin_callback) = pin_callback {
        // pin_callback(vb.0);
        // }

        // Authentication stage 2 and long term key calculation
        // ([Vol 3] Part H, Section 2.3.5.6.5 and C.2.2.4).

        // let a = self.peer_address.unwrap();
        // let b = self.local_address.unwrap();
        let ra = 0;
        // trace!("peer_address = {:02x?}", a.0);
        // trace!("local_address = {:02x?}", b.0);

        // TODO: more calculations!
        // let iob = IoCap::new(make_auth_req().0, false, io_cap);
        let auth_req = AuthReq::new(BondingFlag::Bonding);
        let oob_data = false;
        let io_cap = IoCapabilities::DisplayYesNo as u8;
        // let dh_key = self.dh_key.as_ref().unwrap();

        // let (mac_key, ltk) = dh_key.f5(na, nb, a, b);
        // let eb = mac_key.f6(nb, na, ra, iob, b, a);

        // self.mac_key = Some(mac_key);
        // self.ltk = Some(ltk.0);
        // self.eb = Some(eb);

        Ok(())
    }

    fn handle_pairing_dhkey_check(&self, src_handle: u16, ea: &[u8]) -> Result<(), Error> {
        debug!("[security manager] Handle pairing dhkey check");
        debug!("[security manager] Got ea: {:02x?}", ea);

        // TODO: Do checking

        // TODO: Check dhkey
        // let expected_ea = self
        //     .mac_key
        //     .as_ref()
        //     .unwrap()
        //     .f6(
        //         self.na.unwrap(),
        //         self.nb.unwrap(),
        //         0,
        //         self.ioa.unwrap(),
        //         self.peer_address.unwrap(),
        //         self.local_address.unwrap(),
        //     )
        //     .0
        //     .to_le_bytes();

        // if ea != expected {
        // warn!("DH check failed");
        // }

        let mut data = [0u8; 17];
        data[0] = SM_PAIRING_DHKEY_CHECK;
        // data[1..17].copy_from_slice(self.eb.as_ref().unwrap().0.to_le_bytes());

        // self.write_sm_data(src_handle, &data).await?;
        Ok(())
    }
}
