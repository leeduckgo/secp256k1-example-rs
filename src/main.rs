use secp256k1::rand::rngs::OsRng;
use secp256k1::recovery::{RecoverableSignature, RecoveryId};
use secp256k1::{Error, Message, PublicKey, Secp256k1, SecretKey, Signature, Signing, Verification};
use bitcoin_hashes::{sha256, Hash};

fn main(){
    let (seckey, pubkey) = generate_keys();
    let msg = b"This is some message";
    let sig = sign_msg(msg, seckey);
    verify_msg_sig(msg, sig, pubkey);
    let (recovery_id, sig) = sign_compact(msg, seckey);
    recover_pubkey(msg, sig, recovery_id);
}

/// https://github.com/rust-bitcoin/rust-secp256k1/blob/master/examples/generate_keys.rs
fn generate_keys() -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let mut rng = OsRng::new().unwrap();
    // First option:
    //let (seckey, pubkey) = secp.generate_keypair(&mut rng);

    //assert_eq!(pubkey, PublicKey::from_secret_key(&secp, &seckey));
    
    // Second option:
    let seckey = SecretKey::new(&mut rng);
    println!("privkey: {:?}", seckey);
    let pubkey = PublicKey::from_secret_key(&secp, &seckey);
    println!("pubkey: {:?}", pubkey);
    (seckey, pubkey)
}
///https://github.com/rust-bitcoin/rust-secp256k1/blob/master/examples/sign_verify.rs
fn sign_msg(msg: &[u8], seckey: SecretKey) -> Vec<u8> {
    let secp = Secp256k1::new();
    let signature = sign(&secp, msg, seckey).unwrap();
    println!("signature: {:?}", signature);
    let serialized_sig = signature.serialize_compact();
    println!("serialized sig: {:?}", serialized_sig);
    serialized_sig.to_vec()
}

fn sign_compact(msg: &[u8], seckey: SecretKey) -> (RecoveryId, Vec<u8>) {
    let secp = Secp256k1::new();
    let signature = sign_recovery(&secp, msg, seckey).unwrap();
    let (recovery_id, serialized_sig) = signature.serialize_compact();
    println!("signature compacted: {:?}", serialized_sig);
    println!("recovery id: {:?}", recovery_id);
    (recovery_id, serialized_sig.to_vec())
}

fn verify_msg_sig(msg: &[u8], sig: Vec<u8>, pubkey: PublicKey){
    let secp = Secp256k1::new();
    let result = verify(&secp, msg, sig, pubkey).unwrap();
    println!("verify result: {:?}", result)
}

fn recover_pubkey(msg: &[u8],sig: Vec<u8>,recovery_id: RecoveryId) {
    let secp = Secp256k1::new();
    let pubkey = recover(&secp, msg, sig, recovery_id);
    println!("pubkey recovered: {:?}", pubkey)
}

fn verify<C: Verification>(secp: &Secp256k1<C>, msg: &[u8], sig: Vec<u8>, pubkey: PublicKey) -> Result<bool, Error> {
    let msg = sha256::Hash::hash(msg);
    let msg = Message::from_slice(&msg)?;
    let sig = Signature::from_compact(&sig)?;

    Ok(secp.verify(&msg, &sig, &pubkey).is_ok())
}

fn sign<C: Signing>(secp: &Secp256k1<C>, msg: &[u8], seckey: SecretKey) -> Result<Signature, Error> {
    let msg = sha256::Hash::hash(msg);
    let msg = Message::from_slice(&msg)?;
    Ok(secp.sign(&msg, &seckey))
}


fn sign_recovery<C: Signing>(secp: &Secp256k1<C>, msg: &[u8], seckey: SecretKey) -> Result<RecoverableSignature, Error> {
    let msg = sha256::Hash::hash(msg);
    let msg = Message::from_slice(&msg)?;
    Ok(secp.sign_recoverable(&msg, &seckey))
}

fn recover<C: Verification>(secp: &Secp256k1<C>,msg: &[u8],sig: Vec<u8>,recovery_id: RecoveryId) -> Result<PublicKey, Error> {
    let msg = sha256::Hash::hash(msg);
    let msg = Message::from_slice(&msg)?;
    let sig = RecoverableSignature::from_compact(&sig, recovery_id)?;

    secp.recover(&msg, &sig)
}

