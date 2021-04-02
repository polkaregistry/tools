// SPDX-License-Identifier: GPL-3.0-or-later
// This file is part of Polkaregistry.
//
// Copyright (c) 2021 Wei Tang.
//
// Polkaregistry is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Polkaregistry is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Polkaregistry. If not, see <http://www.gnu.org/licenses/>.

use crate::SR25519;
use sp_keystore::SyncCryptoStore;
use sp_core::crypto::{Ss58Codec, Ss58AddressFormat};
use sp_core::sr25519::Public;
use sp_core::hexdisplay::HexDisplay;

pub struct MatrixProof {
    pub username: String,
    pub address: String,
}

impl MatrixProof {
    pub fn payload(&self) -> String {
        format!("Polkaregistry proof: I am {} on Matrix and own address {} on Polkadot.", self.username, self.address)
    }

    pub fn signature(&self, keystore: &dyn SyncCryptoStore) -> String {
        let payload = self.payload().into_bytes();
        let (public, version) = Public::from_ss58check_with_version(&self.address).expect("ss58 decoding failed");
        assert_eq!(version, Ss58AddressFormat::PolkadotAccount);
        let signature = SyncCryptoStore::sign_with(keystore, SR25519, &public.into(), &payload).expect("signature failed");
        format!("0x{:?}", HexDisplay::from(&signature))
    }

    pub fn message(&self, keystore: &dyn SyncCryptoStore) -> String {
        let payload = self.payload();
        let signature = self.signature(keystore);
        format!("{} {}", payload, signature)
    }
}