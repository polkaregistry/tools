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

mod twitter;
mod github;
mod eeid;
mod matrix;
mod website;

pub use twitter::TweetProof;
pub use github::GistProof;
pub use eeid::EEIDProof;
pub use matrix::MatrixProof;
pub use website::WebsiteProof;

use sp_core::crypto::KeyTypeId;

/// Key type for generic Sr 25519 key.
pub const SR25519: KeyTypeId = KeyTypeId(*b"sr25");