use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct FingerprintResult {
    fingerprint: Vec<u8>,
    verifier: Vec<u8>,
}

#[wasm_bindgen]
impl FingerprintResult {
    #[wasm_bindgen(getter)]
    pub fn fingerprint(&self) -> Vec<u8> {
        self.fingerprint.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn verifier(&self) -> Vec<u8> {
        self.verifier.clone()
    }
}

#[wasm_bindgen]
pub fn generate_fingerprint() -> FingerprintResult {
    let (fingerprint, verifier) = rgp::generate_fingerprint();

    FingerprintResult {
        fingerprint: fingerprint.into(),
        verifier: verifier.into(),
    }
}

#[wasm_bindgen]
pub struct DhKeysResult {
    private: Vec<u8>,
    public: Vec<u8>,
}

#[wasm_bindgen]
impl DhKeysResult {
    #[wasm_bindgen(getter)]
    pub fn private(&self) -> Vec<u8> {
        self.private.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn public(&self) -> Vec<u8> {
        self.public.clone()
    }
}

#[wasm_bindgen]
pub fn generate_dh_keys() -> DhKeysResult {
    let (private, public) = rgp::generate_dh_keys();

    DhKeysResult {
        private: private.into(),
        public: public.into(),
    }
}

#[wasm_bindgen]
pub fn encrypt_dh(
    fingerprint: Vec<u8>,
    content: Vec<u8>,
    private_key: Vec<u8>,
    public_keys: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let fixed_fingerprint: [u8; 32] = match fingerprint.try_into() {
        Ok(f) => f,
        Err(_) => return Err("failed to convert fingerprint to 32 len array".into()),
    };

    let fixed_private_key: [u8; 32] = match private_key.try_into() {
        Ok(f) => f,
        Err(_) => return Err("failed to convert private_key to 32 len array".into()),
    };

    let mut fixed_public_keys = vec![];

    for public_key in public_keys.chunks_exact(32) {
        let fixed_public_key: [u8; 32] = match public_key.try_into() {
            Ok(f) => f,
            Err(_) => return Err("failed to convert public_key to 32 len array".into()),
        };

        fixed_public_keys.push(fixed_public_key);
    }

    let encrypted_content = match rgp::encrypt(
        fixed_fingerprint,
        content.clone(),
        rgp::Encrypt::Dh(fixed_private_key, &fixed_public_keys, None),
    ) {
        Ok((encrypted_content, _)) => encrypted_content,
        Err(err) => return Err(err.into()),
    };

    Ok(encrypted_content)
}
