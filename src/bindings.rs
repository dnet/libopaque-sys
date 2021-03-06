/* automatically generated by rust-bindgen 0.59.2 */

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct __BindgenBitfieldUnit<Storage> {
    storage: Storage,
}
impl<Storage> __BindgenBitfieldUnit<Storage> {
    #[inline]
    pub const fn new(storage: Storage) -> Self {
        Self { storage }
    }
}
impl<Storage> __BindgenBitfieldUnit<Storage>
where
    Storage: AsRef<[u8]> + AsMut<[u8]>,
{
    #[inline]
    pub fn get_bit(&self, index: usize) -> bool {
        debug_assert!(index / 8 < self.storage.as_ref().len());
        let byte_index = index / 8;
        let byte = self.storage.as_ref()[byte_index];
        let bit_index = if cfg!(target_endian = "big") {
            7 - (index % 8)
        } else {
            index % 8
        };
        let mask = 1 << bit_index;
        byte & mask == mask
    }
    #[inline]
    pub fn set_bit(&mut self, index: usize, val: bool) {
        debug_assert!(index / 8 < self.storage.as_ref().len());
        let byte_index = index / 8;
        let byte = &mut self.storage.as_mut()[byte_index];
        let bit_index = if cfg!(target_endian = "big") {
            7 - (index % 8)
        } else {
            index % 8
        };
        let mask = 1 << bit_index;
        if val {
            *byte |= mask;
        } else {
            *byte &= !mask;
        }
    }
    #[inline]
    pub fn get(&self, bit_offset: usize, bit_width: u8) -> u64 {
        debug_assert!(bit_width <= 64);
        debug_assert!(bit_offset / 8 < self.storage.as_ref().len());
        debug_assert!((bit_offset + (bit_width as usize)) / 8 <= self.storage.as_ref().len());
        let mut val = 0;
        for i in 0..(bit_width as usize) {
            if self.get_bit(i + bit_offset) {
                let index = if cfg!(target_endian = "big") {
                    bit_width as usize - 1 - i
                } else {
                    i
                };
                val |= 1 << index;
            }
        }
        val
    }
    #[inline]
    pub fn set(&mut self, bit_offset: usize, bit_width: u8, val: u64) {
        debug_assert!(bit_width <= 64);
        debug_assert!(bit_offset / 8 < self.storage.as_ref().len());
        debug_assert!((bit_offset + (bit_width as usize)) / 8 <= self.storage.as_ref().len());
        for i in 0..(bit_width as usize) {
            let mask = 1 << i;
            let val_bit_is_set = val & mask == mask;
            let index = if cfg!(target_endian = "big") {
                bit_width as usize - 1 - i
            } else {
                i
            };
            self.set_bit(index + bit_offset, val_bit_is_set);
        }
    }
}
pub type __uint8_t = ::std::os::raw::c_uchar;
pub type __uint16_t = ::std::os::raw::c_ushort;
pub type size_t = ::std::os::raw::c_ulong;
#[doc = "struct to store the IDs of the user/server."]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Opaque_Ids {
    #[doc = "< length of idU, most useful if idU is binary"]
    pub idU_len: u16,
    #[doc = "< pointer to the id of the user/client in the opaque protocol"]
    pub idU: *mut u8,
    #[doc = "< length of idS, needed for binary ids"]
    pub idS_len: u16,
    #[doc = "< pointer to the id of the server in the opaque protocol"]
    pub idS: *mut u8,
}
#[test]
fn bindgen_test_layout_Opaque_Ids() {
    assert_eq!(
        ::std::mem::size_of::<Opaque_Ids>(),
        32usize,
        concat!("Size of: ", stringify!(Opaque_Ids))
    );
    assert_eq!(
        ::std::mem::align_of::<Opaque_Ids>(),
        8usize,
        concat!("Alignment of ", stringify!(Opaque_Ids))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<Opaque_Ids>())).idU_len as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(Opaque_Ids),
            "::",
            stringify!(idU_len)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<Opaque_Ids>())).idU as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(Opaque_Ids),
            "::",
            stringify!(idU)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<Opaque_Ids>())).idS_len as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(Opaque_Ids),
            "::",
            stringify!(idS_len)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<Opaque_Ids>())).idS as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(Opaque_Ids),
            "::",
            stringify!(idS)
        )
    );
}
#[doc = "struct to store various extra protocol information."]
#[doc = ""]
#[doc = "This is defined by the RFC to be used to bind extra"]
#[doc = "session-specific parameters to the current session."]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Opaque_App_Infos {
    pub info: *const u8,
    pub info_len: size_t,
    pub einfo: *const u8,
    pub einfo_len: size_t,
}
#[test]
fn bindgen_test_layout_Opaque_App_Infos() {
    assert_eq!(
        ::std::mem::size_of::<Opaque_App_Infos>(),
        32usize,
        concat!("Size of: ", stringify!(Opaque_App_Infos))
    );
    assert_eq!(
        ::std::mem::align_of::<Opaque_App_Infos>(),
        8usize,
        concat!("Alignment of ", stringify!(Opaque_App_Infos))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<Opaque_App_Infos>())).info as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(Opaque_App_Infos),
            "::",
            stringify!(info)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<Opaque_App_Infos>())).info_len as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(Opaque_App_Infos),
            "::",
            stringify!(info_len)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<Opaque_App_Infos>())).einfo as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(Opaque_App_Infos),
            "::",
            stringify!(einfo)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<Opaque_App_Infos>())).einfo_len as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(Opaque_App_Infos),
            "::",
            stringify!(einfo_len)
        )
    );
}
pub const Opaque_PkgTarget_NotPackaged: Opaque_PkgTarget = 0;
#[doc = "< field is encrypted"]
pub const Opaque_PkgTarget_InSecEnv: Opaque_PkgTarget = 1;
#[doc = "< field is plaintext, but authenticated"]
pub const Opaque_PkgTarget_InClrEnv: Opaque_PkgTarget = 2;
#[doc = " enum to define the handling of various fields packed in the opaque envelope"]
pub type Opaque_PkgTarget = ::std::os::raw::c_uchar;
#[doc = " configuration of the opaque envelope fields"]
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct Opaque_PkgConfig {
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 2usize]>,
}
#[test]
fn bindgen_test_layout_Opaque_PkgConfig() {
    assert_eq!(
        ::std::mem::size_of::<Opaque_PkgConfig>(),
        2usize,
        concat!("Size of: ", stringify!(Opaque_PkgConfig))
    );
    assert_eq!(
        ::std::mem::align_of::<Opaque_PkgConfig>(),
        1usize,
        concat!("Alignment of ", stringify!(Opaque_PkgConfig))
    );
}
impl Opaque_PkgConfig {
    #[inline]
    pub fn skU(&self) -> Opaque_PkgTarget {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(0usize, 2u8) as u8) }
    }
    #[inline]
    pub fn set_skU(&mut self, val: Opaque_PkgTarget) {
        unsafe {
            let val: u8 = ::std::mem::transmute(val);
            self._bitfield_1.set(0usize, 2u8, val as u64)
        }
    }
    #[inline]
    pub fn pkU(&self) -> Opaque_PkgTarget {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(2usize, 2u8) as u8) }
    }
    #[inline]
    pub fn set_pkU(&mut self, val: Opaque_PkgTarget) {
        unsafe {
            let val: u8 = ::std::mem::transmute(val);
            self._bitfield_1.set(2usize, 2u8, val as u64)
        }
    }
    #[inline]
    pub fn pkS(&self) -> Opaque_PkgTarget {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(4usize, 2u8) as u8) }
    }
    #[inline]
    pub fn set_pkS(&mut self, val: Opaque_PkgTarget) {
        unsafe {
            let val: u8 = ::std::mem::transmute(val);
            self._bitfield_1.set(4usize, 2u8, val as u64)
        }
    }
    #[inline]
    pub fn idU(&self) -> Opaque_PkgTarget {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(6usize, 2u8) as u8) }
    }
    #[inline]
    pub fn set_idU(&mut self, val: Opaque_PkgTarget) {
        unsafe {
            let val: u8 = ::std::mem::transmute(val);
            self._bitfield_1.set(6usize, 2u8, val as u64)
        }
    }
    #[inline]
    pub fn idS(&self) -> Opaque_PkgTarget {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(8usize, 2u8) as u8) }
    }
    #[inline]
    pub fn set_idS(&mut self, val: Opaque_PkgTarget) {
        unsafe {
            let val: u8 = ::std::mem::transmute(val);
            self._bitfield_1.set(8usize, 2u8, val as u64)
        }
    }
    #[inline]
    pub fn new_bitfield_1(
        skU: Opaque_PkgTarget,
        pkU: Opaque_PkgTarget,
        pkS: Opaque_PkgTarget,
        idU: Opaque_PkgTarget,
        idS: Opaque_PkgTarget,
    ) -> __BindgenBitfieldUnit<[u8; 2usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 2usize]> = Default::default();
        __bindgen_bitfield_unit.set(0usize, 2u8, {
            let skU: u8 = unsafe { ::std::mem::transmute(skU) };
            skU as u64
        });
        __bindgen_bitfield_unit.set(2usize, 2u8, {
            let pkU: u8 = unsafe { ::std::mem::transmute(pkU) };
            pkU as u64
        });
        __bindgen_bitfield_unit.set(4usize, 2u8, {
            let pkS: u8 = unsafe { ::std::mem::transmute(pkS) };
            pkS as u64
        });
        __bindgen_bitfield_unit.set(6usize, 2u8, {
            let idU: u8 = unsafe { ::std::mem::transmute(idU) };
            idU as u64
        });
        __bindgen_bitfield_unit.set(8usize, 2u8, {
            let idS: u8 = unsafe { ::std::mem::transmute(idS) };
            idS as u64
        });
        __bindgen_bitfield_unit
    }
}
extern "C" {
    #[doc = "This function implements the storePwdFile function from the paper"]
    #[doc = "it is not specified by the RFC. This function runs on the server"]
    #[doc = "and creates a new output record rec of secret key material. The"]
    #[doc = "server needs to implement the storage of this record and any"]
    #[doc = "binding to user names or as the paper suggests sid."]
    #[doc = ""]
    #[doc = "@param [in] pwdU - the users password"]
    #[doc = "@param [in] pwdU_len - length of the users password"]
    #[doc = "@param [in] skS - in case of global server keys this is the servers"]
    #[doc = "private key, should be set to NULL if per/user keys are to be"]
    #[doc = "generated"]
    #[doc = "@param [in] cfg - configuration of the opaque envelope, see"]
    #[doc = "Opaque_PkgConfig"]
    #[doc = "@param [in] ids - the ids of the user and server, see Opaque_Ids"]
    #[doc = "@param [out] rec - the opaque record the server needs to"]
    #[doc = "store. this is a pointer to memory allocated by the caller,"]
    #[doc = "and must be large enough to hold the record and take into"]
    #[doc = "account the variable length of idU and idS in case these are"]
    #[doc = "included in the envelope."]
    #[doc = "@param [out] export_key - optional pointer to pre-allocated (and"]
    #[doc = "protected) memory for an extra_key that can be used to"]
    #[doc = "encrypt/authenticate additional data."]
    #[doc = "@return the function returns 0 if everything is correct"]
    #[must_use]
    pub fn opaque_Register(
        pwdU: *const u8,
        pwdU_len: u16,
        skS: *const u8,
        cfg: *const Opaque_PkgConfig,
        ids: *const Opaque_Ids,
        rec: *mut u8,
        export_key: *mut u8,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    #[doc = "This function initiates a new OPAQUE session, is the same as the"]
    #[doc = "function defined in the paper with the name usrSession."]
    #[doc = ""]
    #[doc = "@param [in] pwdU - users input password"]
    #[doc = "@param [in] pwdU_len - length of the users password"]
    #[doc = "@param [out] sec - private context, it is essential that the memory"]
    #[doc = "allocate for this buffer be **OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len**."]
    #[doc = "The User should protect the sec value (e.g. with sodium_mlock())"]
    #[doc = "until opaque_RecoverCredentials."]
    #[doc = "@param [out] pub - the message to be sent to the server"]
    #[doc = "@return the function returns 0 if everything is correct"]
    #[must_use]
    pub fn opaque_CreateCredentialRequest(
        pwdU: *const u8,
        pwdU_len: u16,
        sec: *mut u8,
        pub_: *mut u8,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    #[doc = "This is the same function as defined in the paper with name"]
    #[doc = "srvSession name. This function runs on the server and"]
    #[doc = "receives the output pub from the user running opaque_CreateCredentialRequest(),"]
    #[doc = "furthermore the server needs to load the user record created when"]
    #[doc = "registering the user with opaque_Register() or"]
    #[doc = "opaque_StoreUserRecord(). These input parameters are"]
    #[doc = "transformed into a secret/shared session key sk and a response resp"]
    #[doc = "to be sent back to the user."]
    #[doc = "@param [in] pub - the pub output of the opaque_CreateCredentialRequest()"]
    #[doc = "@param [in] rec - the recorded created during \"registration\" and stored by the server"]
    #[doc = "@param [in] ids - the id if the client and server"]
    #[doc = "@param [in] infos - various extra (unspecified) protocol information as recommended by the rfc."]
    #[doc = "@param [out] resp - servers response to be sent to the client where"]
    #[doc = "it is used as input into opaque_RecoverCredentials() - caller must allocate including envU_len: e.g.:"]
    #[doc = "uint8_t resp[OPAQUE_SERVER_SESSION_LEN+envU_len];"]
    #[doc = "@param [out] sk - the shared secret established between the user & server"]
    #[doc = "@param [out] sec - the current context necessary for the explicit"]
    #[doc = "authentication of the user in opaque_UserAuth(). This"]
    #[doc = "param is optional if no explicit user auth is necessary it can be"]
    #[doc = "set to NULL"]
    #[doc = "@return the function returns 0 if everything is correct"]
    #[must_use]
    pub fn opaque_CreateCredentialResponse(
        pub_: *const u8,
        rec: *const u8,
        ids: *const Opaque_Ids,
        infos: *const Opaque_App_Infos,
        resp: *mut u8,
        sk: *mut u8,
        sec: *mut u8,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    #[doc = "This is the same function as defined in the paper with the"]
    #[doc = "usrSessionEnd name. It is run by the user and receives as input the"]
    #[doc = "response from the previous server opaque_CreateCredentialResponse()"]
    #[doc = "function as well as the sec value from running the"]
    #[doc = "opaque_CreateCredentialRequest() function that initiated this"]
    #[doc = "instantiation of this protocol, All these input parameters are"]
    #[doc = "transformed into a shared/secret session key pk, which should be"]
    #[doc = "the same as the one calculated by the"]
    #[doc = "opaque_CreateCredentialResponse() function."]
    #[doc = ""]
    #[doc = "@param [in] resp - the response sent from the server running opaque_CreateCredentialResponse()"]
    #[doc = "@param [in] sec - the private sec output of the client initiating"]
    #[doc = "this instantiation of this protocol using opaque_CreateCredentialRequest()"]
    #[doc = "@param [in] pkS - if cfg.pkS == NotPackaged pkS *must* be supplied here, otherwise it must be NULL"]
    #[doc = "@param [in] cfg - the configuration of the envelope secret and cleartext part"]
    #[doc = "@param [in] infos - various extra (unspecified) protocol information"]
    #[doc = "as recommended by the rfc"]
    #[doc = "@param [in/out] ids - if ids were packed in the envelope - as given by"]
    #[doc = "the cfg param -, they are returned in this struct - if either"]
    #[doc = "cfg.idS or cfg.idU is NotPackaged, then the according value must be"]
    #[doc = "set in this struct before calling opaque_RecoverCredentials"]
    #[doc = "@param [out] sk - the shared secret established between the user & server"]
    #[doc = "@param [out] authU - the authentication code to be sent to the server"]
    #[doc = "in case explicit user authentication is required"]
    #[doc = "@param [out] export_key - key used to encrypt/authenticate extra"]
    #[doc = "material not stored directly in the envelope"]
    #[doc = "@return the function returns 0 if the protocol is executed correctly"]
    #[must_use]
    pub fn opaque_RecoverCredentials(
        resp: *const u8,
        sec: *const u8,
        pkS: *const u8,
        cfg: *const Opaque_PkgConfig,
        infos: *const Opaque_App_Infos,
        ids: *mut Opaque_Ids,
        sk: *mut u8,
        authU: *mut u8,
        export_key: *mut u8,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    #[doc = "Explicit User Authentication."]
    #[doc = ""]
    #[doc = "This is a function not explicitly specified in the original paper. In the"]
    #[doc = "irtf cfrg draft authentication is done using a hmac of the session"]
    #[doc = "transcript with different keys coming out of a hkdf after the key"]
    #[doc = "exchange."]
    #[doc = ""]
    #[doc = "@param [in] sec - the context returned by opaque_CreateCredentialResponse()"]
    #[doc = "@param [in] authU is the authentication token sent by the user."]
    #[doc = "@return the function returns 0 if the hmac verifies correctly."]
    #[must_use]
    pub fn opaque_UserAuth(sec: *const u8, authU: *const u8) -> ::std::os::raw::c_int;
}
extern "C" {
    #[doc = "Initial step to start registering a new user/client with the server."]
    #[doc = "The user inputs its password pwdU, and receives a secret context sec"]
    #[doc = "and a blinded value M as output. sec should be protected until"]
    #[doc = "step 3 of this registration protocol and the value M should be"]
    #[doc = "passed to the server."]
    #[doc = "@param [in] pwdU - the users password"]
    #[doc = "@param [in] pwdU_len - length of the users password"]
    #[doc = "@param [out] sec - a secret context needed for the 3rd step in this"]
    #[doc = "registration protocol - this needs to be protected and sanitized"]
    #[doc = "after usage."]
    #[doc = "@param [out] M - the blinded hashed password as per the OPRF,"]
    #[doc = "this needs to be sent to the server together with any other"]
    #[doc = "important and implementation specific info such as user/client id,"]
    #[doc = "envelope configuration etc."]
    #[doc = "@return the function returns 0 if everything is correct."]
    #[must_use]
    pub fn opaque_CreateRegistrationRequest(
        pwdU: *const u8,
        pwdU_len: u16,
        sec: *mut u8,
        M: *mut u8,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    #[doc = "Server evaluates OPRF and creates a user-specific public/private keypair"]
    #[doc = ""]
    #[doc = "The server receives M from the users invocation of its"]
    #[doc = "opaque_CreateRegistrationRequest() function, it outputs a value sec"]
    #[doc = "which needs to be protected until step 4 by the server. This"]
    #[doc = "function also outputs a value pub which needs to be passed to the"]
    #[doc = "user."]
    #[doc = "@param [in] M - the blinded password as per the OPRF."]
    #[doc = "@param [out] sec - the private key and the OPRF secret of the server."]
    #[doc = "@param [out] pub - the evaluated OPRF and pubkey of the server to"]
    #[doc = "be passed to the client into opaque_FinalizeRequest()"]
    #[doc = "@return the function returns 0 if everything is correct."]
    #[must_use]
    pub fn opaque_CreateRegistrationResponse(
        M: *const u8,
        sec: *mut u8,
        pub_: *mut u8,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    #[doc = "2nd step of registration: Server evaluates OPRF - Global Server Key Version"]
    #[doc = ""]
    #[doc = "This function is essentially the same as"]
    #[doc = "opaque_CreateRegistrationResponse(), except this function does not"]
    #[doc = "generate a per-user long-term key, but instead expects the servers"]
    #[doc = "to supply a long-term pubkey as a parameter, this might be one"]
    #[doc = "unique global key, or it might be a per-user key derived from a"]
    #[doc = "server secret."]
    #[doc = ""]
    #[doc = "This function is called CreateRegistrationResponse in the rfc."]
    #[doc = "The server receives M from the users invocation of its"]
    #[doc = "opaque_CreateRegistrationRequest() function, it outputs a value sec"]
    #[doc = "which needs to be protected until step 4 by the server. This"]
    #[doc = "function also outputs a value pub which needs to be passed to the"]
    #[doc = "user."]
    #[doc = "@param [in] M - the blinded password as per the OPRF."]
    #[doc = "@param [in] pkS - the servers long-term pubkey"]
    #[doc = "@param [out] sec - the private key and the OPRF secret of the server."]
    #[doc = "@param [out] pub - the evaluated OPRF and pubkey of the server to"]
    #[doc = "be passed to the client into opaque_FinalizeRequest()"]
    #[doc = "@return the function returns 0 if everything is correct."]
    #[must_use]
    pub fn opaque_Create1kRegistrationResponse(
        M: *const u8,
        pkS: *const u8,
        sec: *mut u8,
        pub_: *mut u8,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    #[doc = "Client finalizes registration by concluding the OPRF, generating"]
    #[doc = "its own keys and enveloping it all."]
    #[doc = ""]
    #[doc = "This function is called FinalizeRequest in the rfc.  This function"]
    #[doc = "is run by the user, taking as input the context sec that was an"]
    #[doc = "output of the user running opaque_CreateRegistrationRequest(), and the"]
    #[doc = "output pub from the server of opaque_CreateRegistrationResponse()."]
    #[doc = ""]
    #[doc = "@param [in] sec - output from opaque_CreateRegistrationRequest(),"]
    #[doc = "should be sanitized after usage."]
    #[doc = "@param [in] pub - response from the server running"]
    #[doc = "opaque_CreateRegistrationResponse()"]
    #[doc = "@param [in] cfg - the configuration of the envelope secret and cleartext part"]
    #[doc = "@param [in] ids - if ids are to be packed in the envelope - as given by"]
    #[doc = "the cfg param"]
    #[doc = "@param [out] rec - the opaque record to be stored at the server"]
    #[doc = "this is a pointer to memory allocated by the caller, and must be"]
    #[doc = "large enough to hold the record and take into account the variable"]
    #[doc = "length of idU and idS in case these are included in the envelope."]
    #[doc = "@param [out] export_key - key used to encrypt/authenticate extra"]
    #[doc = "material not stored directly in the envelope"]
    #[doc = ""]
    #[doc = "@return the function returns 0 if everything is correct."]
    #[must_use]
    pub fn opaque_FinalizeRequest(
        sec: *const u8,
        pub_: *const u8,
        cfg: *const Opaque_PkgConfig,
        ids: *const Opaque_Ids,
        rec: *mut u8,
        export_key: *mut u8,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    #[doc = "Final Registration step - server adds own info to the record to be stored."]
    #[doc = ""]
    #[doc = "The rfc does not explicitly specify this function."]
    #[doc = "The server combines the sec value from its run of its"]
    #[doc = "opaque_CreateRegistrationResponse() function with the rec output of"]
    #[doc = "the users opaque_FinalizeRequest() function, creating the"]
    #[doc = "final record, which should be the same as the output of the 1-step"]
    #[doc = "storePwdFile() init function of the paper. The server should save"]
    #[doc = "this record in combination with a user id and/or sid value as"]
    #[doc = "suggested in the paper."]
    #[doc = ""]
    #[doc = "@param [in] sec - the private value of the server running"]
    #[doc = "opaque_CreateRegistrationResponse() in step 2 of the registration"]
    #[doc = "protocol"]
    #[doc = "@param [in/out] rec - input the record from the client running"]
    #[doc = "opaque_FinalizeRequest() - output the final record to be"]
    #[doc = "stored by the server this is a pointer to memory allocated by the"]
    #[doc = "caller, and must be large enough to hold the record and take into"]
    #[doc = "account the variable length of idU and idS in case these are"]
    #[doc = "included in the envelope."]
    pub fn opaque_StoreUserRecord(sec: *const u8, rec: *mut u8);
}
extern "C" {
    #[doc = "Final Registration step Global Server Key Version - server adds own info to the record to be stored."]
    #[doc = ""]
    #[doc = "this function essentially does the same as"]
    #[doc = "opaque_StoreUserRecord() except that it expects the server"]
    #[doc = "to provide its secret key. This server secret key might be one"]
    #[doc = "global secret key used for all users, or it might be a per-user"]
    #[doc = "unique key derived from a secret server seed."]
    #[doc = ""]
    #[doc = "The rfc does not explicitly specify this function."]
    #[doc = "The server combines the sec value from its run of its"]
    #[doc = "opaque_CreateRegistrationResponse() function with the rec output of"]
    #[doc = "the users opaque_FinalizeRequest() function, creating the"]
    #[doc = "final record, which should be the same as the output of the 1-step"]
    #[doc = "storePwdFile() init function of the paper. The server should save"]
    #[doc = "this record in combination with a user id and/or sid value as"]
    #[doc = "suggested in the paper."]
    #[doc = ""]
    #[doc = "@param [in] sec - the private value of the server running"]
    #[doc = "opaque_CreateRegistrationResponse() in step 2 of the registration"]
    #[doc = "protocol"]
    #[doc = "@param [in] skS - the servers long-term private key"]
    #[doc = "@param [in/out] rec - input the record from the client running"]
    #[doc = "opaque_FinalizeRequest() - output the final record to be"]
    #[doc = "stored by the server this is a pointer to memory allocated by the"]
    #[doc = "caller, and must be large enough to hold the record and take into"]
    #[doc = "account the variable length of idU and idS in case these are"]
    #[doc = "included in the envelope."]
    pub fn opaque_Store1kUserRecord(sec: *const u8, skS: *const u8, rec: *mut u8);
}
extern "C" {
    #[doc = "This helper function calculates the length of the envelope in bytes."]
    #[doc = ""]
    #[doc = "The returned size should be OPAQUE_ENVELOPE_META_LEN + SecEnv_len +"]
    #[doc = "ClrEnv_len."]
    #[doc = ""]
    #[doc = "@param [in] cfg - the configuration of the envelope's secret and cleartext"]
    #[doc = "parts"]
    #[doc = "@param [in] ids - the IDs of the user and server that are only needed if we"]
    #[doc = "pack one of the IDs into the envelope as given by the cfg param"]
    #[doc = ""]
    #[doc = "@return the function returns the size of the envelope."]
    pub fn opaque_envelope_len(cfg: *const Opaque_PkgConfig, ids: *const Opaque_Ids) -> size_t;
}
