use zeroize::Zeroizing;

#[cfg(windows)]
fn transform(bytes: &[u8], protect: bool) -> Result<Zeroizing<Vec<u8>>, String> {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        },
    };
    use zeroize::Zeroize;

    if bytes.is_empty() || bytes.len() > 32 * 1024 {
        return Err("Invalid protected key size.".into());
    }
    struct Output(CRYPT_INTEGER_BLOB);
    impl Drop for Output {
        fn drop(&mut self) {
            if !self.0.pbData.is_null() {
                // DPAPI owns this allocation. Erase it before releasing it with LocalFree.
                unsafe {
                    std::slice::from_raw_parts_mut(self.0.pbData, self.0.cbData as usize).zeroize();
                    LocalFree(self.0.pbData.cast());
                }
            }
        }
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr().cast_mut(),
    };
    let mut output = Output(CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    });
    // Both APIs read the input blob and allocate the output. Null optional arguments
    // disable UI prompts; omitting LOCAL_MACHINE keeps protection scoped to the user.
    let success = unsafe {
        if protect {
            CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.0,
            )
        } else {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.0,
            )
        }
    };
    if success == 0 {
        return Err(format!(
            "Windows key protection failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if output.0.pbData.is_null() || output.0.cbData == 0 {
        return Err("Windows key protection returned no data.".into());
    }
    // The successful API result guarantees that this allocation contains cbData bytes.
    let copied =
        unsafe { std::slice::from_raw_parts(output.0.pbData, output.0.cbData as usize).to_vec() };
    Ok(Zeroizing::new(copied))
}

#[cfg(not(windows))]
fn transform(_: &[u8], _: bool) -> Result<Zeroizing<Vec<u8>>, String> {
    Err("Protected CA storage currently requires Windows DPAPI.".into())
}

pub fn protect(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    transform(bytes, true)
}
pub fn unprotect(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    transform(bytes, false)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn protects_and_restores_under_current_user() {
        let input = b"wireforge-test-private-key";
        let protected = protect(input).unwrap();
        assert_ne!(protected.as_slice(), input);
        assert_eq!(unprotect(&protected).unwrap().as_slice(), input);
        assert!(unprotect(b"invalid protected data").is_err());
    }
}
