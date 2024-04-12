use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;
use std::{fs::File, time::SystemTime};

use candid::Principal;
use ic_agent::Identity;
use pocket_ic::{PocketIc, PocketIcBuilder};

use super::identity::generate_random_identity;

pub struct TestEnv {
    pic: PocketIc,
    canister_id: Principal,
    root_ic_key: Vec<u8>,
    controller: Principal,
}

impl TestEnv {
    /// Creates a new test env from the wasm module,
    /// setting the PIC time to the current time.
    pub fn new(wasm_module: Vec<u8>) -> Self {
        let pic = PocketIcBuilder::new()
            // NNS subnet needed to retrieve the root key
            .with_nns_subnet()
            .with_application_subnet()
            .build();

        // set ic time to current time
        pic.set_time(SystemTime::now());

        let controller = generate_random_identity().sender().unwrap();

        let app_subnet = pic.topology().get_app_subnets()[0];
        let canister_id = pic.create_canister_on_subnet(Some(controller), None, app_subnet);
        pic.add_cycles(canister_id, 1_000_000_000_000_000); // we don't care about the cycles

        pic.install_canister(
            canister_id,
            wasm_module,
            candid::encode_args(()).unwrap(),
            Some(controller),
        );

        let root_ic_key = pic.root_key().unwrap();

        Self {
            pic,
            canister_id,
            root_ic_key,
            controller,
        }
    }

    pub fn pic(&self) -> &PocketIc {
        &self.pic
    }

    pub fn canister_id(&self) -> Principal {
        self.canister_id
    }

    pub fn controller(&self) -> Principal {
        self.controller
    }

    /// Sets the canister time by specifying the duration elapsed from [SystemTime::UNIX_EPOCH].
    pub fn set_canister_time(&self, elapsed: Duration) {
        self.pic.set_time(SystemTime::UNIX_EPOCH + elapsed);
        // produce and advance by some blocks to set the time correctly
        for _ in 0..10 {
            self.pic.tick();
        }
    }

    pub fn root_ic_key(&self) -> &[u8] {
        &self.root_ic_key
    }
}

pub fn create_test_env() -> TestEnv {
    let wasm_path = std::env::var("TEST_CANISTER_WASM_PATH").unwrap();
    let wasm_module = load_canister_wasm_from_path(&PathBuf::from(wasm_path));

    TestEnv::new(wasm_module)
}

/// Simulates a canister upgrade, using the same wasm module.
pub fn upgrade_canister(env: &TestEnv) {
    let wasm_path = std::env::var("TEST_CANISTER_WASM_PATH").unwrap();
    let wasm_module = load_canister_wasm_from_path(&PathBuf::from(wasm_path));

    env.pic()
        .upgrade_canister(
            env.canister_id(),
            wasm_module,
            candid::encode_args(()).unwrap(),
            Some(env.controller()),
        )
        .unwrap();
}

fn load_canister_wasm_from_path(path: &PathBuf) -> Vec<u8> {
    let mut file = File::open(path)
        .unwrap_or_else(|_| panic!("Failed to open file: {}", path.to_str().unwrap()));
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).expect("Failed to read file");
    bytes
}
