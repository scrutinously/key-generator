use bip39::Mnemonic;
use chia_bls::{SecretKey, PublicKey, G1Element, G2Element, derive_keys};
use chia_wallet::{standard::standard_puzzle_hash, standard::DEFAULT_HIDDEN_PUZZLE_HASH};
use chia_wallet::DeriveSynthetic;
use rand_core::{OsRng, RngCore};
use bech32::ToBase32;
use sha2::{digest::FixedOutput, Sha256, Digest};
use std::fs::File;
use std::io::Write;
use inquire::Confirm;

pub struct Key {
    mnemonic: String,
    secret_key: SecretKey,
    public_key: PublicKey,
    farmer_key: PublicKey,
    pool_key: PublicKey,
    wallet: PublicKey,
    address0: Vec<String>,
}
fn derive_path_hardened(key: &SecretKey, path: &[u32]) -> SecretKey {
    let mut derived = key.derive_hardened(path[0]);
    for idx in &path[1..] {
        derived = derived.derive_hardened(*idx);
    }
    derived
}
impl Key { 
    pub fn generate() -> Key {
        // user inputs a phrase to be used as additional entropy to RNG
        println!("Enter a phrase to generate entropy: ");
        let mut user_entropy = String::new();
        std::io::stdin().read_line(&mut user_entropy).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(user_entropy);
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        // combine entropy with user_entropy
        hasher.update(entropy);
        let result: [u8; 32] = hasher.finalize_fixed().into();
        let mnemonic = Mnemonic::from_entropy(&result).expect("could not generate mnemonic");
        let seed = mnemonic.to_seed("");
        let sk = SecretKey::from_seed(&seed);
        let pk = sk.public_key();
        let farmer = derive_path_hardened(&sk, &[12381_u32, 8444, 0, 0]).public_key();
        let pool = derive_path_hardened(&sk, &[12381_u32, 8444, 1, 0]).public_key();
        let wallet = derive_keys::master_to_wallet_unhardened_intermediate(&pk);
        let mut address = Vec::new();
        for i in 0..10 {
            let add_pk = derive_keys::master_to_wallet_unhardened(&pk, i);
            let pk_syn = add_pk.derive_synthetic(&DEFAULT_HIDDEN_PUZZLE_HASH);
            let ph = standard_puzzle_hash(&pk_syn);
            let cur_address = bech32::encode("xch", ph.to_base32(), bech32::Variant::Bech32m).unwrap();
            address.push(cur_address);        
        }
        Key {
            mnemonic: mnemonic.to_string(),
            secret_key: sk,
            public_key: pk,
            farmer_key: farmer,
            pool_key: pool,
            wallet: wallet,
            address0: address,
        }
    }
    // Create an option to export the public keys and address list
    pub fn export(&self) {
        let mut export = String::new();
        export.push_str(&format!("Master Public Key:   {}", hex::encode(self.public_key.to_bytes())));
        export.push_str("\n");
        export.push_str(&format!("Farmer Public Key:   {}", hex::encode(self.farmer_key.to_bytes())));
        export.push_str("\n");
        export.push_str(&format!("Pool Public Key:     {}", hex::encode(self.pool_key.to_bytes())));
        export.push_str("\n");
        export.push_str(&format!("Wallet Observer Key: {}", hex::encode(self.wallet.to_bytes())));
        export.push_str("\n");
        export.push_str("\n");
        for i in 0..10 {
            export.push_str(&format!("Address {i}: {}", self.address0[i]));
            export.push_str("\n");
        }
        let filename = format!("{}.txt", &self.public_key.get_fingerprint());
        let mut file = File::create(filename).expect("Unable to create file");
        file.write_all(export.as_bytes()).expect("Unable to write data");
    }
}

fn main() {
    loop {
        let key = Key::generate();
        println!("Mnemonic:");
        println!("{:?}", key.mnemonic);
        println!("-----------------------------------------------");
        println!("Fingerprint:         {}", key.public_key.get_fingerprint());
        println!("Master Public Key:   {}", hex::encode(key.public_key.to_bytes()));
        println!("Farmer Public Key:   {}", hex::encode(key.farmer_key.to_bytes()));
        println!("Pool Public Key:     {}", hex::encode(key.pool_key.to_bytes()));
        println!("Wallet Observer Key: {}", hex::encode(key.wallet.to_bytes()));
        for i in 0..10 {
            println!("Address {i}: {}", key.address0[i]);
        }
        println!("-----------------------------------------------");
        let export = Confirm::new("Would you like to export the Public Keys and addresses? ")
            .with_default(false).prompt();
        match export {
            Ok(true) => key.export(),
            Ok(false) => (),
            Err(_) => println!("Invalid input, not exporting keys"),
        }
        let again = Confirm::new("Would you like to generate another key? ")
            .with_default(false).prompt();
        
        match again {
            Ok(true) => (),
            Ok(false) => break,
            Err(_) => break,
        }
    }
}
