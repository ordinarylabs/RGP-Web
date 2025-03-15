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
