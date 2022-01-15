#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!("./bindings.rs");

use libsodium_sys::{crypto_auth_hmacsha512_BYTES, crypto_auth_hmacsha512_KEYBYTES,
    crypto_core_ristretto255_BYTES, crypto_core_ristretto255_SCALARBYTES,
    crypto_hash_sha512_BYTES, crypto_scalarmult_BYTES, crypto_scalarmult_SCALARBYTES,
    crypto_hash_sha512_statebytes, crypto_scalarmult_base};

const OPAQUE_SHARED_SECRETBYTES: usize = 32;
const OPAQUE_NONCE_BYTES: u32 = 32;
const OPAQUE_USER_RECORD_LEN: usize = (
    crypto_core_ristretto255_SCALARBYTES +
    crypto_scalarmult_SCALARBYTES +
    crypto_scalarmult_BYTES +
    crypto_scalarmult_BYTES) as usize + std::mem::size_of::<u32>();
const OPAQUE_USER_SESSION_PUBLIC_LEN: usize = (
    crypto_core_ristretto255_BYTES +
    crypto_scalarmult_BYTES +
    OPAQUE_NONCE_BYTES) as usize;
const OPAQUE_USER_SESSION_SECRET_LEN: usize = (
    crypto_core_ristretto255_SCALARBYTES +
    crypto_scalarmult_SCALARBYTES +
    OPAQUE_NONCE_BYTES +
    crypto_core_ristretto255_BYTES) as usize + std::mem::size_of::<u16>();
const OPAQUE_SERVER_SESSION_LEN: usize = (
    crypto_core_ristretto255_BYTES +
    crypto_scalarmult_BYTES +
    OPAQUE_NONCE_BYTES +
    crypto_auth_hmacsha512_BYTES) as usize + std::mem::size_of::<u32>();
const OPAQUE_REGISTER_USER_SEC_LEN: usize =
    (crypto_core_ristretto255_SCALARBYTES as usize) + std::mem::size_of::<u16>();
const OPAQUE_REGISTER_PUBLIC_LEN: usize = (
    crypto_core_ristretto255_BYTES +
    crypto_scalarmult_BYTES) as usize;
const OPAQUE_REGISTER_SECRET_LEN: usize = (
    crypto_scalarmult_SCALARBYTES +
    crypto_core_ristretto255_SCALARBYTES) as usize;

#[cfg(test)]
mod tests {
    use crate::*;

    const pwdU: &[u8; 4] = b"asdf";
    const pwdU_len: u16 = pwdU.len() as u16;

    fn opaque_server_auth_ctx_len() -> usize {
        crypto_auth_hmacsha512_KEYBYTES as usize +
            unsafe { crypto_hash_sha512_statebytes() }
    }

    #[test]
    fn register_with_global_server_key() {
        let OPAQUE_SERVER_AUTH_CTX_LEN = opaque_server_auth_ctx_len();
        let mut idU = b"idU".clone();
        let mut idS = b"idS".clone();
        let ids = Opaque_Ids {
            idU_len: idU.len() as u16,
            idU: idU.as_mut_ptr(),
            idS_len: idS.len() as u16,
            idS: idS.as_mut_ptr(),
        };
        let mut idU1 = [0u8; 1024];
        let mut idS1 = [0u8; 1024];
        let mut ids1 = Opaque_Ids {
            idU_len: idU1.len() as u16,
            idU: idU1.as_mut_ptr(),
            idS_len: idS1.len() as u16,
            idS: idS1.as_mut_ptr(),
        };
        let mut rsecU: Vec<u8> = Vec::with_capacity(
            OPAQUE_REGISTER_USER_SEC_LEN + pwdU_len as usize);
        let mut M = [0u8; crypto_core_ristretto255_BYTES as usize];
        let mut pkS = [0u8; crypto_scalarmult_BYTES as usize];
        let mut rsecS = [0u8; OPAQUE_REGISTER_SECRET_LEN];
        let mut rpub = [0u8; OPAQUE_REGISTER_PUBLIC_LEN];
        let cfg = Opaque_PkgConfig {
            _bitfield_1: Opaque_PkgConfig::new_bitfield_1(
                /* skU */ Opaque_PkgTarget_InSecEnv,
                /* pkU */ Opaque_PkgTarget_NotPackaged,
                /* pkS */ Opaque_PkgTarget_NotPackaged,
                /* idU */ Opaque_PkgTarget_InSecEnv,
                /* idS */ Opaque_PkgTarget_InClrEnv),
            };
        let envU_len = unsafe {
            opaque_envelope_len(&cfg, &ids) as usize
        };
        let mut rec: Vec<u8> = Vec::with_capacity(OPAQUE_USER_RECORD_LEN +
                                                  envU_len as usize);
        let mut export_key  = [0u8; crypto_hash_sha512_BYTES as usize];
        let mut export_key1 = [0u8; crypto_hash_sha512_BYTES as usize];
        let skS: Vec<u8> = (0..32).collect();
        let mut secU: Vec<u8> = Vec::with_capacity(
            OPAQUE_USER_SESSION_SECRET_LEN + pwdU_len as usize);
        let mut pub_ = [0u8; OPAQUE_USER_SESSION_PUBLIC_LEN];
        let mut resp: Vec<u8> = Vec::with_capacity(
            OPAQUE_SERVER_SESSION_LEN + envU_len as usize);
        let mut sk  = [0u8; OPAQUE_SHARED_SECRETBYTES];
        let mut sk1 = [0u8; OPAQUE_SHARED_SECRETBYTES];
        let mut secS: Vec<u8> = Vec::with_capacity(OPAQUE_SERVER_AUTH_CTX_LEN);
        let mut authU = [0u8; crypto_auth_hmacsha512_BYTES as usize];

        unsafe {
            crypto_scalarmult_base(pkS.as_mut_ptr(), skS.as_ptr());

            assert_eq!(0, opaque_CreateRegistrationRequest(
                    pwdU.as_ptr(), pwdU_len, rsecU.as_mut_ptr(), M.as_mut_ptr()));
            assert_eq!(0, opaque_Create1kRegistrationResponse(
                    M.as_ptr(), pkS.as_ptr(), rsecS.as_mut_ptr(), rpub.as_mut_ptr()));
            assert_eq!(0, opaque_FinalizeRequest(
                    rsecU.as_ptr(), rpub.as_ptr(), &cfg, &ids,
                    rec.as_mut_ptr(), export_key.as_mut_ptr()));
            opaque_Store1kUserRecord(rsecS.as_ptr(), skS.as_ptr(), rec.as_mut_ptr());
            assert_eq!(0, opaque_CreateCredentialRequest(
                    pwdU.as_ptr(), pwdU_len, secU.as_mut_ptr(), pub_.as_mut_ptr()));
            assert_eq!(0, opaque_CreateCredentialResponse(
                    pub_.as_ptr(), rec.as_ptr(), &ids, std::ptr::null(),
                    resp.as_mut_ptr(), sk.as_mut_ptr(), secS.as_mut_ptr()));
            assert_eq!(0, opaque_RecoverCredentials(
                    resp.as_ptr(), secU.as_ptr(), pkS.as_ptr(), &cfg,
                    std::ptr::null(), &mut ids1, sk1.as_mut_ptr(),
                    authU.as_mut_ptr(), export_key1.as_mut_ptr()));
        }
        assert_eq!(ids.idU_len, ids1.idU_len);
        assert_eq!(ids.idS_len, ids1.idS_len);
        assert_eq!(idU, idU1[..(ids.idU_len as usize)]);
        assert_eq!(idS, idS1[..(ids.idS_len as usize)]);
        assert_eq!(export_key, export_key1);
        assert_eq!(sk, sk1);
        assert_eq!(0, unsafe { opaque_UserAuth(secS.as_ptr(), authU.as_ptr()) });
    }

    #[test]
    fn test_opaque() {
        let OPAQUE_SERVER_AUTH_CTX_LEN = opaque_server_auth_ctx_len();

        let skS: *const u8 = std::ptr::null();
        let cfg = Opaque_PkgConfig {
            _bitfield_1: Opaque_PkgConfig::new_bitfield_1(
                /* skU */ Opaque_PkgTarget_InSecEnv,
                /* pkU */ Opaque_PkgTarget_NotPackaged,
                /* pkS */ Opaque_PkgTarget_InClrEnv,
                /* idU */ Opaque_PkgTarget_InSecEnv,
                /* idS */ Opaque_PkgTarget_InClrEnv),
            };
        let mut idU = b"user".clone();
        let mut idS = b"server".clone();
        let ids = Opaque_Ids {
            idU_len: idU.len() as u16,
            idU: idU.as_mut_ptr(),
            idS_len: idS.len() as u16,
            idS: idS.as_mut_ptr(),
        };
        let mut export_key_x = [0u8; crypto_hash_sha512_BYTES as usize];
        let mut export_key = [0u8; crypto_hash_sha512_BYTES as usize];
        let envU_len = unsafe {
            opaque_envelope_len(&cfg, &ids) as usize
        };
        let mut rec: Vec<u8> = Vec::with_capacity(OPAQUE_USER_RECORD_LEN + envU_len);

        // register user
        let reg_result = unsafe {
            opaque_Register(pwdU.as_ptr(), pwdU_len, skS, &cfg, &ids,
                            rec.as_mut_ptr(), export_key.as_mut_ptr())
        };
        assert_eq!(reg_result, 0);

        // initiate login
        let mut sec: Vec<u8> = Vec::with_capacity(
            OPAQUE_USER_SESSION_SECRET_LEN + pwdU.len());
        let mut pub_ = [0u8; OPAQUE_USER_SESSION_PUBLIC_LEN];
        unsafe {
            assert_eq!(0, opaque_CreateCredentialRequest(
                    pwdU.as_ptr(), pwdU_len, sec.as_mut_ptr(), pub_.as_mut_ptr()));
        }

        let mut resp: Vec<u8> = Vec::with_capacity(OPAQUE_SERVER_SESSION_LEN + envU_len);
        let mut sk = [0u8; 32];
        let mut ctx: Vec<u8> = Vec::with_capacity(OPAQUE_SERVER_AUTH_CTX_LEN);

        let mut info = b"info".clone();
        let mut einfo = b"einfo".clone();
        let infos = Opaque_App_Infos {
            info: info.as_mut_ptr(),
            info_len: info.len() as u64,
            einfo: einfo.as_mut_ptr(),
            einfo_len: einfo.len() as u64,
        };
        let ccr_result = unsafe {
            opaque_CreateCredentialResponse(pub_.as_ptr(), rec.as_ptr(),
                                            &ids, &infos, resp.as_mut_ptr(),
                                            sk.as_mut_ptr(), ctx.as_mut_ptr())
        };
        assert_eq!(ccr_result, 0);

        let mut pk = [0u8; 32];
        let mut authU = [0u8; crypto_auth_hmacsha512_BYTES as usize];
        // must be big enough to fit ids
        let mut idU_rec: Vec<u8> = Vec::with_capacity(ids.idU_len as usize);
        let mut idS_rec: Vec<u8> = Vec::with_capacity(ids.idS_len as usize);
        let mut ids1 = Opaque_Ids {
            idU_len: idU_rec.capacity() as u16,
            idU: idU_rec.as_mut_ptr(),
            idS_len: idS_rec.capacity() as u16,
            idS: idS_rec.as_mut_ptr(),
        };
        if cfg.idU() == Opaque_PkgTarget_NotPackaged {
            ids1.idU_len = ids.idU_len;
            idU_rec.copy_from_slice(&idU);
        }
        if cfg.idS() == Opaque_PkgTarget_NotPackaged {
            ids1.idS_len = ids.idS_len;
            idS_rec.copy_from_slice(&idS);
        }
        let pkS: *const u8 = if cfg.pkS() == Opaque_PkgTarget_NotPackaged {
            panic!("not implemented for now")
        } else { std::ptr::null() };
        let rc_result = unsafe { opaque_RecoverCredentials(
            resp.as_ptr(), sec.as_ptr(), pkS, &cfg, &infos, &mut ids1,
            pk.as_mut_ptr(), authU.as_mut_ptr(), export_key_x.as_mut_ptr())
        };
        assert_eq!(rc_result, 0);
        assert_eq!(sk, pk);
        assert_eq!(export_key, export_key_x);

        assert_ne!(-1, unsafe { opaque_UserAuth(ctx.as_ptr(), authU.as_ptr()) });

        // variant where user registration does not leak secrets to server
        let mut M = [0u8; crypto_core_ristretto255_BYTES as usize];
        let mut usr_ctx: Vec<u8> = Vec::with_capacity(
            OPAQUE_REGISTER_USER_SEC_LEN + pwdU_len as usize);
        assert_eq!(0, unsafe {
            opaque_CreateRegistrationRequest(pwdU.as_ptr(), pwdU_len,
                                             usr_ctx.as_mut_ptr(), M.as_mut_ptr())
        });
        let mut rsec = [0u8; OPAQUE_REGISTER_SECRET_LEN];
        let mut rpub = [0u8; OPAQUE_REGISTER_PUBLIC_LEN];
        assert_eq!(0, unsafe {
            opaque_CreateRegistrationResponse(M.as_ptr(), rsec.as_mut_ptr(),
                                              rpub.as_mut_ptr())
        });
        let mut rrec: Vec<u8> = Vec::with_capacity(
            OPAQUE_USER_RECORD_LEN + envU_len as usize);
        assert_eq!(0, unsafe {
            opaque_FinalizeRequest(usr_ctx.as_ptr(), rpub.as_ptr(), &cfg, &ids,
                                   rrec.as_mut_ptr(), export_key.as_mut_ptr())
        });
        unsafe {
            opaque_StoreUserRecord(rsec.as_ptr(), rrec.as_mut_ptr());
        }
        assert_eq!(0, unsafe {
            opaque_CreateCredentialRequest(pwdU.as_ptr(), pwdU_len,
                                           sec.as_mut_ptr(), pub_.as_mut_ptr())
        });
        assert_eq!(0, unsafe {
            opaque_CreateCredentialResponse(pub_.as_ptr(), rrec.as_ptr(), &ids,
                                           std::ptr::null(), resp.as_mut_ptr(),
                                           sk.as_mut_ptr(), ctx.as_mut_ptr())
        });
        assert_eq!(0, unsafe {
            opaque_RecoverCredentials(resp.as_ptr(), sec.as_ptr(), pkS,
                                      &cfg, std::ptr::null(), &mut ids1,
                                      pk.as_mut_ptr(), authU.as_mut_ptr(),
                                      export_key.as_mut_ptr())
        });
        assert_eq!(sk, pk);
        assert_ne!(-1, unsafe { opaque_UserAuth(ctx.as_ptr(), authU.as_ptr()) });
    }
}
