// Copyright 2018-2019 Parity Technologies (UK) Ltd.
// This file is part of Substrate.

// Substrate is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Substrate is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Substrate.  If not, see <http://www.gnu.org/licenses/>.

//! Low-level types used throughout the Substrate code.

#![warn(missing_docs)]

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(alloc))]

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use log::info;
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

use balances;
use balances::Call as BalancesCall;
use client::block_builder::api::BlockBuilder;
use client::runtime_api::ConstructRuntimeApi;
use consensus_common::{BlockOrigin, ImportBlock, ForkChoiceStrategy};
use consensus_common::block_import::BlockImport;
use indices;
use keyring::sr25519::Keyring;
use sr_primitives::generic::{Era, BlockId};
use sr_primitives::traits::{As, Block, Extrinsic, Header, ProvideRuntimeApi, BlockNumberToHash};
use node_runtime::{Call, CheckedExtrinsic, UncheckedExtrinsic};
use substrate_service::{FactoryBlock, FactoryFullConfiguration, FullClient, new_client, ServiceFactory};
use parity_codec::{Decode, Encode};
use primitives::{H256, sr25519};
use primitives::crypto::Pair;

use srml_support::dispatch::Result;
use srml_support::{StorageValue, StorageMap, IsSubType, decl_module, decl_storage, decl_event, ensure};

fn gen_random_account_id(seed: u64) -> node_primitives::AccountId {
	let mut rng: StdRng = SeedableRng::seed_from_u64(seed);

	let mut r = [0; 32];
	for i in 0..32 {
		let a = rng.gen::<u8>();
		r[i] = a;
	}

	let pair: sr25519::Pair = sr25519::Pair::from_seed(r);
	pair.public().into()
}

fn sign<F: ServiceFactory>(xt: CheckedExtrinsic, hash: H256, block_no: u64) -> UncheckedExtrinsic {
	let mut c = 0;
	if block_no > 0 {
		c = block_no - 1;
	}
	match xt.signed {
		Some((signed, index)) => {
			let era = Era::mortal(256, c);
			let payload = (index.into(), xt.function, era, hash);
			let key = Keyring::from_public(&signed).unwrap();
			let signature = payload.using_encoded(|b| {
				if b.len() > 256 {
					key.sign(&sr_io::blake2_256(b))
				} else {
					key.sign(b)
				}
			}).into();
			UncheckedExtrinsic {
				signature: Some((indices::address::Address::Id(signed), signature, payload.0, era)),
				function: payload.1,
			}
		}
		None => UncheckedExtrinsic {
			signature: None,
			function: xt.function,
		},
	}
}

/// Factory
pub fn factory<F>(
	config: FactoryFullConfiguration<F>,
	num: u64,
) -> cli::error::Result<()>
	where
		F: ServiceFactory,
		F::RuntimeApi: ConstructRuntimeApi<FactoryBlock<F>, FullClient<F>>,
		FullClient<F>: ProvideRuntimeApi,
		<FullClient<F> as ProvideRuntimeApi>::Api: BlockBuilder<FactoryBlock<F>>,
{
	info!("Creating {} transactions...", num);

	let client = new_client::<F>(&config)?;

	let api = client.runtime_api();

	let cont = true;

	let mut hash = client.best_block_header()?.hash();

	let block = client.block(&BlockId::Hash(hash))?;
	let b = block.unwrap();

	let start = SystemTime::now();
	let mut last_ts: u64 = start.duration_since(UNIX_EPOCH)
		.expect("Time went backwards").as_secs();

	let start: u64 = client.info()?.chain.best_number.as_() + 1;
	let mut block_no = start;

	while cont && block_no - 1 < start + num {
		info!("Creating block {}", block_no);

		let alice: node_primitives::AccountId = Keyring::Alice.into();

		let to: node_primitives::AccountId = gen_random_account_id(block_no);

		// index contains amount of prior transactions on this account
		let index = block_no - 1;

		let xt = sign::<F>(CheckedExtrinsic {
			signed: Some((alice.into(), index)),
			function: Call::Balances(
				BalancesCall::transfer(
					indices::address::Address::Id(
						to.clone().into(),
					),
					1337
				)
			)
		}, hash, block_no);

		let mut block = client.new_block().unwrap();
		let dec = Decode::decode(&mut &xt.encode()[..]).unwrap();
		block.push(dec).unwrap();

		let new_ts = last_ts + 9999;
		last_ts = new_ts;
		let c = CheckedExtrinsic {
			signed: None,
			function: Call::Timestamp(timestamp::Call::set(new_ts)),
		};
		let foo = sign::<F>(c, hash, block_no);

		block.push(Decode::decode(&mut &foo.encode()[..]).unwrap()).unwrap();

		let block = block.bake().unwrap();
		hash = block.header().hash();

		info!("Created block {} with hash {}. Transferring from Alice to {}.", block_no, hash, to);

		let import = ImportBlock {
			origin: BlockOrigin::File,
			header: block.header().clone(),
			post_digests: Vec::new(),
			body: Some(block.extrinsics().to_vec()),
			finalized: false,
			justification: None,
			auxiliary: Vec::new(),
			fork_choice: ForkChoiceStrategy::LongestChain,
		};
		client.import_block(import, HashMap::new()).unwrap();

		info!("Imported block {}", block_no);
		block_no += 1;
	}

	info!("Finished importing {} blocks", block_no-1);

	Ok(())
}
