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

use structopt::StructOpt;
use sp_core::crypto::{Pair, Ss58Codec, Ss58AddressFormat};
use sp_keystore::SyncCryptoStore;
use sc_keystore::LocalKeystore;
use polkaregistry::{SR25519, TweetProof, GistProof, EEIDProof, MatrixProof, WebsiteProof};

#[derive(Debug, StructOpt)]
#[structopt(name = "polkaregistry", about = "Trustless and free identity registrar for Polkadot and Kulupu.")]
struct Opt {
    #[structopt(subcommand)]
    command: Command,
}

#[derive(Debug, StructOpt)]
enum Command {
    Keystore(KeystoreCommand),
    Sign(SignCommand),
    Verify,
}

#[derive(Debug, StructOpt)]
enum KeystoreCommand {
    Generate,
    Import {
        suri: String,
    }
}

#[derive(Debug, StructOpt)]
enum SignCommand {
    Twitter {
        username: String,
        address: String,
    },
    Github {
        username: String,
        address: String,
    },
    EEID {
        legal_name: String,
        address: String,
    },
    Matrix {
        username: String,
        address: String,
    },
    Website {
        domain: String,
        address: String,
    },
}

fn main() {
    let opt = Opt::from_args();

    let base_path = directories::ProjectDirs::from("", "", "polkaregistry").expect("project dir does not exist");
    let keystore_path = base_path.config_dir().join("keystore");
    let keystore = LocalKeystore::open(keystore_path, None).expect("creating keystore failed");

    match opt.command {
        Command::Keystore(KeystoreCommand::Generate) => {
            let public = keystore.sr25519_generate_new(SR25519, None).expect("generating keys failed");
            println!("Generated address: {:?}", public.to_ss58check_with_version(Ss58AddressFormat::PolkadotAccount));
        },
        Command::Keystore(KeystoreCommand::Import { suri } ) => {
            let pair = sp_core::sr25519::Pair::from_string(
                &suri,
                None,
            ).expect("invalid seed");

            keystore.insert_unknown(
                SR25519,
                &suri,
                pair.public().as_ref(),
            ).expect("insert failed");

            println!("Inserted address: {:?}", pair.public().to_ss58check_with_version(Ss58AddressFormat::PolkadotAccount));
        },
        Command::Sign(SignCommand::Twitter { username, address }) => {
            let proof = TweetProof { username, address };
            let message = proof.message(&keystore);
            println!("{}", message);
        },
        Command::Sign(SignCommand::Github { username, address }) => {
            let proof = GistProof { username, address };
            let message = proof.message(&keystore);
            println!("{}", message);
        },
        Command::Sign(SignCommand::EEID { legal_name, address }) => {
            let proof = EEIDProof { legal_name, address };
            let message = proof.message(&keystore);
            println!("{}", message);
        },
        Command::Sign(SignCommand::Matrix { username, address }) => {
            let proof = MatrixProof { username, address };
            let message = proof.message(&keystore);
            println!("{}", message);
        },
        Command::Sign(SignCommand::Website { domain, address }) => {
            let proof = WebsiteProof { domain, address };
            let message = proof.message(&keystore);
            println!("{}", message);
        },
        Command::Verify => unimplemented!(),
    }
}
