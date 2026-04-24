use std::collections::HashMap;
use std::convert::TryFrom;
use std::env;
use std::fs;
use std::mem;
use std::path::{Path, PathBuf};
use std::ptr;
use std::slice;
use std::sync::{Mutex, OnceLock};

use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use pkcs11_sys::*;
use tpmctl_core::tpm::{
    parse_tpm_handle_literal as core_parse_tpm_handle_literal, tcti_name_conf_from_env,
};
use tss_esapi::{
    Context as TpmContext,
    constants::{StructureTag, tss::TPM2_RH_NULL},
    handles::TpmHandle,
    interface_types::{algorithm::HashingAlgorithm, session_handles::AuthSession},
    structures::{Auth, Digest, HashScheme, HashcheckTicket, Signature, SignatureScheme},
    tss2_esys::{TPM2B_DIGEST, TPMT_TK_HASHCHECK},
};

const SLOT_ID: CK_SLOT_ID = 1;
const USER_PIN: &[u8] = b"";
const P256_EC_PARAMS_DER: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

static PROVIDER: OnceLock<Mutex<ProviderState>> = OnceLock::new();

#[derive(Default)]
struct ProviderState {
    initialized: bool,
    next_session: CK_SESSION_HANDLE,
    objects: Vec<KeyObject>,
    sessions: HashMap<CK_SESSION_HANDLE, SessionState>,
}

#[derive(Clone)]
struct KeyObject {
    label: String,
    id: Vec<u8>,
    key_ref: TpmKeyRef,
    ec_point_der: Vec<u8>,
}

#[derive(Clone)]
enum TpmKeyRef {
    Persistent(TpmHandle),
    ContextFile(PathBuf),
}

#[derive(Default)]
struct SessionState {
    find_results: Vec<CK_OBJECT_HANDLE>,
    find_index: usize,
    sign_key: Option<CK_OBJECT_HANDLE>,
    logged_in: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ObjectKind {
    Public,
    Private,
}

fn provider() -> &'static Mutex<ProviderState> {
    PROVIDER.get_or_init(|| Mutex::new(ProviderState::default()))
}

fn with_state<T>(f: impl FnOnce(&mut ProviderState) -> T) -> T {
    let mut guard = provider().lock().expect("provider mutex poisoned");
    f(&mut guard)
}

fn load_objects() -> Vec<KeyObject> {
    let mut objects = Vec::new();
    if let Some(object) = load_single_key_from_env() {
        objects.push(object);
    }
    objects
}

fn load_single_key_from_env() -> Option<KeyObject> {
    let handle_ref = env::var("TPM2_PKCS11_KEY_HANDLE").ok()?;
    let key_ref = parse_tpm_key_ref(&handle_ref).ok()?;
    let label = env::var("TPM2_PKCS11_KEY_LABEL").unwrap_or_else(|_| "tpm2-key".to_string());
    let id = env::var("TPM2_PKCS11_KEY_ID")
        .map(|value| value.into_bytes())
        .unwrap_or_else(|_| label.as_bytes().to_vec());

    let public_key = if let Ok(path) = env::var("TPM2_PKCS11_KEY_PUBLIC_DER") {
        load_public_key_der(Path::new(&path)).ok()?
    } else if let Ok(path) = env::var("TPM2_PKCS11_KEY_PUBLIC_PEM") {
        load_public_key_pem(Path::new(&path)).ok()?
    } else {
        return None;
    };

    let sec1 = public_key.to_encoded_point(false).as_bytes().to_vec();
    let mut ec_point_der = Vec::with_capacity(sec1.len() + 2);
    ec_point_der.push(0x04);
    ec_point_der.push(sec1.len() as u8);
    ec_point_der.extend_from_slice(&sec1);

    Some(KeyObject {
        label,
        id,
        key_ref,
        ec_point_der,
    })
}

fn parse_tpm_key_ref(value: &str) -> Result<TpmKeyRef, String> {
    if let Some(handle) = parse_tpm_handle_literal(value)? {
        return Ok(TpmKeyRef::Persistent(handle));
    }

    let path = PathBuf::from(value);
    if path.is_file() {
        return Ok(TpmKeyRef::ContextFile(path));
    }

    Err(format!(
        "TPM2_PKCS11_KEY_HANDLE must be a TPM handle like 0x81000001 or a context file path; got {value}"
    ))
}

fn parse_tpm_handle_literal(value: &str) -> Result<Option<TpmHandle>, String> {
    core_parse_tpm_handle_literal(value)
}

fn load_public_key_der(path: &Path) -> Result<p256::PublicKey, String> {
    let der = fs::read(path).map_err(|error| error.to_string())?;
    <p256::PublicKey as p256::pkcs8::DecodePublicKey>::from_public_key_der(&der)
        .map_err(|error| error.to_string())
}

fn load_public_key_pem(path: &Path) -> Result<p256::PublicKey, String> {
    let pem = fs::read_to_string(path).map_err(|error| error.to_string())?;
    <p256::PublicKey as p256::pkcs8::DecodePublicKey>::from_public_key_pem(&pem)
        .map_err(|error| error.to_string())
}

fn private_handle(index: usize) -> CK_OBJECT_HANDLE {
    (index as CK_OBJECT_HANDLE) * 2 + 1
}

fn public_handle(index: usize) -> CK_OBJECT_HANDLE {
    (index as CK_OBJECT_HANDLE) * 2 + 2
}

fn resolve_handle(handle: CK_OBJECT_HANDLE, objects: &[KeyObject]) -> Option<(usize, ObjectKind)> {
    if handle == 0 {
        return None;
    }
    let kind = if handle % 2 == 1 {
        ObjectKind::Private
    } else {
        ObjectKind::Public
    };
    let index = ((handle - 1) / 2) as usize;
    objects.get(index)?;
    Some((index, kind))
}

fn tcti_name_conf() -> Result<tss_esapi::tcti_ldr::TctiNameConf, String> {
    tcti_name_conf_from_env()
}

fn load_signing_key(
    context: &mut TpmContext,
    key_ref: &TpmKeyRef,
) -> Result<tss_esapi::handles::ObjectHandle, String> {
    match key_ref {
        TpmKeyRef::Persistent(handle) => context
            .tr_from_tpm_public(*handle)
            .map_err(|error| error.to_string()),
        TpmKeyRef::ContextFile(path) => {
            let bytes = fs::read(path).map_err(|error| error.to_string())?;
            let tpms = unmarshal_tpms_context(&bytes)?;
            context
                .context_load(tpms)
                .map_err(|error| error.to_string())
        }
    }
}

fn unmarshal_tpms_context(bytes: &[u8]) -> Result<tss_esapi::utils::TpmsContext, String> {
    let mut offset = 0;
    let mut native = std::mem::MaybeUninit::uninit();
    let rc = unsafe {
        tss_esapi::tss2_esys::Tss2_MU_TPMS_CONTEXT_Unmarshal(
            bytes.as_ptr(),
            bytes.len() as u64,
            &mut offset,
            native.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(format!("failed to unmarshal TPMS_CONTEXT: rc=0x{rc:08x}"));
    }
    if offset != bytes.len() as u64 {
        return Err("context file had trailing bytes after TPMS_CONTEXT".to_string());
    }
    tss_esapi::utils::TpmsContext::try_from(unsafe { native.assume_init() })
        .map_err(|error| error.to_string())
}

fn hash_algorithm_for_digest_len(len: usize) -> Result<HashingAlgorithm, String> {
    match len {
        32 => Ok(HashingAlgorithm::Sha256),
        48 => Ok(HashingAlgorithm::Sha384),
        64 => Ok(HashingAlgorithm::Sha512),
        other => Err(format!(
            "unsupported digest length {other}; expected 32, 48, or 64 bytes"
        )),
    }
}

fn null_hashcheck_ticket() -> Result<HashcheckTicket, String> {
    HashcheckTicket::try_from(TPMT_TK_HASHCHECK {
        tag: StructureTag::Hashcheck.into(),
        hierarchy: TPM2_RH_NULL,
        digest: TPM2B_DIGEST {
            size: 0,
            buffer: [0; 64],
        },
    })
    .map_err(|error| error.to_string())
}

fn signature_to_raw_ecdsa(signature: Signature) -> Result<Vec<u8>, String> {
    let ecc = match signature {
        Signature::EcDsa(signature) => signature,
        other => return Err(format!("expected ECDSA signature, got {other:?}")),
    };

    let mut out = Vec::with_capacity(64);
    append_padded_scalar(&mut out, ecc.signature_r().value())?;
    append_padded_scalar(&mut out, ecc.signature_s().value())?;
    Ok(out)
}

fn append_padded_scalar(out: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    if value.len() > 32 {
        return Err(format!(
            "ECDSA scalar too large for P-256: {} bytes",
            value.len()
        ));
    }
    out.resize(out.len() + (32 - value.len()), 0);
    out.extend_from_slice(value);
    Ok(())
}

fn sign_with_tpm(key: &KeyObject, digest: &[u8]) -> Result<Vec<u8>, String> {
    let hash_algorithm = hash_algorithm_for_digest_len(digest.len())?;
    let digest = Digest::try_from(digest.to_vec()).map_err(|error| error.to_string())?;
    let scheme = SignatureScheme::EcDsa {
        hash_scheme: HashScheme::new(hash_algorithm),
    };
    let validation = null_hashcheck_ticket()?;

    let mut context = TpmContext::new(tcti_name_conf()?).map_err(|error| error.to_string())?;
    let object = load_signing_key(&mut context, &key.key_ref)?;
    let auth = Auth::try_from(USER_PIN).map_err(|error| error.to_string())?;
    context
        .tr_set_auth(object, auth)
        .map_err(|error| error.to_string())?;

    let key_handle = tss_esapi::handles::KeyHandle::from(object);
    let signature = context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.sign(key_handle, digest, scheme, validation)
        })
        .map_err(|error| error.to_string())?;

    signature_to_raw_ecdsa(signature)
}

fn space_pad<const N: usize>(value: &str) -> [u8; N] {
    let mut out = [b' '; N];
    let bytes = value.as_bytes();
    let len = bytes.len().min(N);
    out[..len].copy_from_slice(&bytes[..len]);
    out
}

unsafe fn template_slice<'a>(
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> &'a mut [CK_ATTRIBUTE] {
    unsafe { slice::from_raw_parts_mut(template, count as usize) }
}

unsafe fn read_bytes<'a>(ptr: CK_VOID_PTR, len: CK_ULONG) -> &'a [u8] {
    unsafe { slice::from_raw_parts(ptr as *const u8, len as usize) }
}

unsafe fn attr_matches_bytes(attr: &CK_ATTRIBUTE, expected: &[u8]) -> bool {
    if attr.pValue.is_null() || attr.ulValueLen as usize != expected.len() {
        return false;
    }
    (unsafe { read_bytes(attr.pValue, attr.ulValueLen) }) == expected
}

unsafe fn attr_matches_bool(attr: &CK_ATTRIBUTE, expected: bool) -> bool {
    if attr.pValue.is_null() || attr.ulValueLen != mem::size_of::<CK_BBOOL>() as CK_ULONG {
        return false;
    }
    let value = unsafe { *(attr.pValue as *const CK_BBOOL) };
    (value != CK_FALSE) == expected
}

unsafe fn attr_matches_ulong(attr: &CK_ATTRIBUTE, expected: CK_ULONG) -> bool {
    if attr.pValue.is_null() || attr.ulValueLen != mem::size_of::<CK_ULONG>() as CK_ULONG {
        return false;
    }
    unsafe { *(attr.pValue as *const CK_ULONG) == expected }
}

unsafe fn matches_template(attrs: &[CK_ATTRIBUTE], object: &KeyObject, kind: ObjectKind) -> bool {
    for attr in attrs {
        match attr.type_ {
            CKA_CLASS => {
                let expected = match kind {
                    ObjectKind::Public => CKO_PUBLIC_KEY,
                    ObjectKind::Private => CKO_PRIVATE_KEY,
                };
                if !unsafe { attr_matches_ulong(attr, expected) } {
                    return false;
                }
            }
            CKA_KEY_TYPE => {
                if !unsafe { attr_matches_ulong(attr, CKK_EC) } {
                    return false;
                }
            }
            CKA_ID => {
                if !unsafe { attr_matches_bytes(attr, &object.id) } {
                    return false;
                }
            }
            CKA_LABEL => {
                if !unsafe { attr_matches_bytes(attr, object.label.as_bytes()) } {
                    return false;
                }
            }
            CKA_TOKEN => {
                if !unsafe { attr_matches_bool(attr, true) } {
                    return false;
                }
            }
            CKA_PRIVATE => {
                if !unsafe { attr_matches_bool(attr, kind == ObjectKind::Private) } {
                    return false;
                }
            }
            CKA_SIGN => {
                if !unsafe { attr_matches_bool(attr, kind == ObjectKind::Private) } {
                    return false;
                }
            }
            CKA_VERIFY => {
                if !unsafe { attr_matches_bool(attr, kind == ObjectKind::Public) } {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

unsafe fn write_attribute_bytes(attr: &mut CK_ATTRIBUTE, value: &[u8]) -> CK_RV {
    let needed = value.len() as CK_ULONG;
    let available = attr.ulValueLen;
    attr.ulValueLen = needed;
    if attr.pValue.is_null() {
        return CKR_OK;
    }
    if available < needed {
        return CKR_BUFFER_TOO_SMALL;
    }
    unsafe { ptr::copy_nonoverlapping(value.as_ptr(), attr.pValue as *mut u8, value.len()) };
    CKR_OK
}

unsafe fn write_attribute_bool(attr: &mut CK_ATTRIBUTE, value: bool) -> CK_RV {
    let needed = mem::size_of::<CK_BBOOL>() as CK_ULONG;
    let available = attr.ulValueLen;
    attr.ulValueLen = needed;
    if attr.pValue.is_null() {
        return CKR_OK;
    }
    if available < needed {
        return CKR_BUFFER_TOO_SMALL;
    }
    unsafe { *(attr.pValue as *mut CK_BBOOL) = if value { CK_TRUE } else { CK_FALSE } };
    CKR_OK
}

unsafe fn write_attribute_ulong(attr: &mut CK_ATTRIBUTE, value: CK_ULONG) -> CK_RV {
    let needed = mem::size_of::<CK_ULONG>() as CK_ULONG;
    let available = attr.ulValueLen;
    attr.ulValueLen = needed;
    if attr.pValue.is_null() {
        return CKR_OK;
    }
    if available < needed {
        return CKR_BUFFER_TOO_SMALL;
    }
    unsafe { *(attr.pValue as *mut CK_ULONG) = value };
    CKR_OK
}

extern "C" fn c_initialize(_args: CK_VOID_PTR) -> CK_RV {
    with_state(|state| {
        if !state.initialized {
            state.objects = load_objects();
            state.next_session = 1;
            state.sessions.clear();
            state.initialized = true;
        }
        CKR_OK
    })
}

extern "C" fn c_finalize(_reserved: CK_VOID_PTR) -> CK_RV {
    with_state(|state| {
        state.initialized = false;
        state.objects.clear();
        state.sessions.clear();
        state.next_session = 0;
        CKR_OK
    })
}

extern "C" fn c_get_info(info: CK_INFO_PTR) -> CK_RV {
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        *info = CK_INFO {
            cryptokiVersion: CK_VERSION {
                major: 2,
                minor: 40,
            },
            manufacturerID: space_pad("tpm2-pkcs11"),
            flags: 0,
            libraryDescription: space_pad("minimal tpm2 pkcs11"),
            libraryVersion: CK_VERSION { major: 0, minor: 1 },
        };
    }
    CKR_OK
}

extern "C" fn c_get_slot_list(
    token_present: CK_BBOOL,
    slot_list: CK_SLOT_ID_PTR,
    count: CK_ULONG_PTR,
) -> CK_RV {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let has_token = with_state(|state| state.initialized && !state.objects.is_empty());
    unsafe {
        if token_present != CK_FALSE && !has_token {
            *count = 0;
            return CKR_OK;
        }
        if slot_list.is_null() {
            *count = 1;
            return CKR_OK;
        }
        if *count < 1 {
            *count = 1;
            return CKR_BUFFER_TOO_SMALL;
        }
        *slot_list = SLOT_ID;
        *count = 1;
    }
    CKR_OK
}

extern "C" fn c_get_slot_info(slot_id: CK_SLOT_ID, info: CK_SLOT_INFO_PTR) -> CK_RV {
    if slot_id != SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        *info = CK_SLOT_INFO {
            slotDescription: space_pad("minimal tpm2 slot"),
            manufacturerID: space_pad("tpm2-pkcs11"),
            flags: CKF_TOKEN_PRESENT,
            hardwareVersion: CK_VERSION { major: 0, minor: 1 },
            firmwareVersion: CK_VERSION { major: 0, minor: 1 },
        };
    }
    CKR_OK
}

extern "C" fn c_get_token_info(slot_id: CK_SLOT_ID, info: CK_TOKEN_INFO_PTR) -> CK_RV {
    if slot_id != SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let count = with_state(|state| state.objects.len() as CK_ULONG);
    unsafe {
        *info = CK_TOKEN_INFO {
            label: space_pad("minimal tpm2 token"),
            manufacturerID: space_pad("tpm2-pkcs11"),
            model: space_pad("TPM2-P256"),
            serialNumber: space_pad("0000000000000001"),
            flags: CKF_TOKEN_INITIALIZED | CKF_LOGIN_REQUIRED,
            ulMaxSessionCount: CK_EFFECTIVELY_INFINITE,
            ulSessionCount: count,
            ulMaxRwSessionCount: CK_EFFECTIVELY_INFINITE,
            ulRwSessionCount: count,
            ulMaxPinLen: 0,
            ulMinPinLen: 0,
            ulTotalPublicMemory: CK_UNAVAILABLE_INFORMATION,
            ulFreePublicMemory: CK_UNAVAILABLE_INFORMATION,
            ulTotalPrivateMemory: CK_UNAVAILABLE_INFORMATION,
            ulFreePrivateMemory: CK_UNAVAILABLE_INFORMATION,
            hardwareVersion: CK_VERSION { major: 0, minor: 1 },
            firmwareVersion: CK_VERSION { major: 0, minor: 1 },
            utcTime: space_pad("0000000000000000"),
        };
    }
    CKR_OK
}

extern "C" fn c_get_mechanism_list(
    slot_id: CK_SLOT_ID,
    mechanism_list: CK_MECHANISM_TYPE_PTR,
    count: CK_ULONG_PTR,
) -> CK_RV {
    if slot_id != SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        if mechanism_list.is_null() {
            *count = 1;
            return CKR_OK;
        }
        if *count < 1 {
            *count = 1;
            return CKR_BUFFER_TOO_SMALL;
        }
        *mechanism_list = CKM_ECDSA;
        *count = 1;
    }
    CKR_OK
}

extern "C" fn c_get_mechanism_info(
    slot_id: CK_SLOT_ID,
    mechanism_type: CK_MECHANISM_TYPE,
    info: CK_MECHANISM_INFO_PTR,
) -> CK_RV {
    if slot_id != SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    if mechanism_type != CKM_ECDSA {
        return CKR_MECHANISM_INVALID;
    }
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        *info = CK_MECHANISM_INFO {
            ulMinKeySize: 256,
            ulMaxKeySize: 256,
            flags: CKF_SIGN | CKF_VERIFY | CKF_EC_NAMEDCURVE,
        };
    }
    CKR_OK
}

extern "C" fn c_open_session(
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
    _application: CK_VOID_PTR,
    _notify: CK_NOTIFY,
    session: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    if slot_id != SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    if session.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if flags & CKF_SERIAL_SESSION == 0 {
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }
    with_state(|state| {
        if !state.initialized {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        let handle = if state.next_session == 0 {
            1
        } else {
            state.next_session
        };
        state.next_session = handle.saturating_add(1);
        state.sessions.insert(handle, SessionState::default());
        unsafe { *session = handle };
        CKR_OK
    })
}

extern "C" fn c_close_session(session: CK_SESSION_HANDLE) -> CK_RV {
    with_state(|state| {
        if state.sessions.remove(&session).is_some() {
            CKR_OK
        } else {
            CKR_SESSION_HANDLE_INVALID
        }
    })
}

extern "C" fn c_close_all_sessions(slot_id: CK_SLOT_ID) -> CK_RV {
    if slot_id != SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    with_state(|state| {
        state.sessions.clear();
        CKR_OK
    })
}

extern "C" fn c_get_session_info(session: CK_SESSION_HANDLE, info: CK_SESSION_INFO_PTR) -> CK_RV {
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    with_state(|state| {
        let Some(session_state) = state.sessions.get(&session) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        unsafe {
            *info = CK_SESSION_INFO {
                slotID: SLOT_ID,
                state: if session_state.logged_in {
                    CKS_RW_USER_FUNCTIONS
                } else {
                    CKS_RO_PUBLIC_SESSION
                },
                flags: CKF_SERIAL_SESSION | CKF_RW_SESSION,
                ulDeviceError: 0,
            };
        }
        CKR_OK
    })
}

extern "C" fn c_login(
    session: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    pin: CK_UTF8CHAR_PTR,
    pin_len: CK_ULONG,
) -> CK_RV {
    if user_type != CKU_USER {
        return CKR_USER_TYPE_INVALID;
    }
    if !pin.is_null() {
        let supplied = unsafe { slice::from_raw_parts(pin, pin_len as usize) };
        if supplied != USER_PIN {
            return CKR_PIN_INCORRECT;
        }
    }
    with_state(|state| {
        let Some(session_state) = state.sessions.get_mut(&session) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        session_state.logged_in = true;
        CKR_OK
    })
}

extern "C" fn c_logout(session: CK_SESSION_HANDLE) -> CK_RV {
    with_state(|state| {
        let Some(session_state) = state.sessions.get_mut(&session) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        session_state.logged_in = false;
        session_state.sign_key = None;
        CKR_OK
    })
}

extern "C" fn c_find_objects_init(
    session: CK_SESSION_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    with_state(|state| {
        let Some(session_state) = state.sessions.get_mut(&session) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        let attrs = if template.is_null() || count == 0 {
            &[][..]
        } else {
            unsafe { template_slice(template, count) }
        };
        session_state.find_results = state
            .objects
            .iter()
            .enumerate()
            .flat_map(|(index, object)| {
                let mut out = Vec::new();
                if unsafe { matches_template(attrs, object, ObjectKind::Private) } {
                    out.push(private_handle(index));
                }
                if unsafe { matches_template(attrs, object, ObjectKind::Public) } {
                    out.push(public_handle(index));
                }
                out
            })
            .collect();
        session_state.find_index = 0;
        CKR_OK
    })
}

extern "C" fn c_find_objects(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE_PTR,
    max_count: CK_ULONG,
    count: CK_ULONG_PTR,
) -> CK_RV {
    if object.is_null() || count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    with_state(|state| {
        let Some(session_state) = state.sessions.get_mut(&session) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        let remaining = session_state
            .find_results
            .len()
            .saturating_sub(session_state.find_index);
        let emit = remaining.min(max_count as usize);
        unsafe {
            for i in 0..emit {
                *object.add(i) = session_state.find_results[session_state.find_index + i];
            }
            *count = emit as CK_ULONG;
        }
        session_state.find_index += emit;
        CKR_OK
    })
}

extern "C" fn c_find_objects_final(session: CK_SESSION_HANDLE) -> CK_RV {
    with_state(|state| {
        let Some(session_state) = state.sessions.get_mut(&session) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        session_state.find_results.clear();
        session_state.find_index = 0;
        CKR_OK
    })
}

extern "C" fn c_get_attribute_value(
    _session: CK_SESSION_HANDLE,
    object_handle: CK_OBJECT_HANDLE,
    template: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> CK_RV {
    if template.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    with_state(|state| {
        let Some((index, kind)) = resolve_handle(object_handle, &state.objects) else {
            return CKR_OBJECT_HANDLE_INVALID;
        };
        let object = &state.objects[index];
        let attrs = unsafe { template_slice(template, count) };
        let mut rv = CKR_OK;
        for attr in attrs {
            let one = unsafe {
                match attr.type_ {
                    CKA_CLASS => write_attribute_ulong(
                        attr,
                        match kind {
                            ObjectKind::Public => CKO_PUBLIC_KEY,
                            ObjectKind::Private => CKO_PRIVATE_KEY,
                        },
                    ),
                    CKA_KEY_TYPE => write_attribute_ulong(attr, CKK_EC),
                    CKA_TOKEN => write_attribute_bool(attr, true),
                    CKA_PRIVATE => write_attribute_bool(attr, kind == ObjectKind::Private),
                    CKA_LABEL => write_attribute_bytes(attr, object.label.as_bytes()),
                    CKA_ID => write_attribute_bytes(attr, &object.id),
                    CKA_EC_PARAMS => write_attribute_bytes(attr, P256_EC_PARAMS_DER),
                    CKA_EC_POINT if kind == ObjectKind::Public => {
                        write_attribute_bytes(attr, &object.ec_point_der)
                    }
                    CKA_VERIFY if kind == ObjectKind::Public => write_attribute_bool(attr, true),
                    CKA_SIGN if kind == ObjectKind::Private => write_attribute_bool(attr, true),
                    CKA_SENSITIVE if kind == ObjectKind::Private => {
                        write_attribute_bool(attr, true)
                    }
                    CKA_EXTRACTABLE if kind == ObjectKind::Private => {
                        write_attribute_bool(attr, false)
                    }
                    CKA_NEVER_EXTRACTABLE if kind == ObjectKind::Private => {
                        write_attribute_bool(attr, true)
                    }
                    CKA_ALWAYS_AUTHENTICATE if kind == ObjectKind::Private => {
                        write_attribute_bool(attr, false)
                    }
                    _ => {
                        attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                        CKR_ATTRIBUTE_TYPE_INVALID
                    }
                }
            };
            if rv == CKR_OK && one != CKR_OK {
                rv = one;
            }
        }
        rv
    })
}

extern "C" fn c_sign_init(
    session: CK_SESSION_HANDLE,
    mechanism: CK_MECHANISM_PTR,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    if mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        if (*mechanism).mechanism != CKM_ECDSA {
            return CKR_MECHANISM_INVALID;
        }
    }
    with_state(|state| {
        let Some((_index, kind)) = resolve_handle(key, &state.objects) else {
            return CKR_KEY_HANDLE_INVALID;
        };
        if kind != ObjectKind::Private {
            return CKR_KEY_HANDLE_INVALID;
        }
        let Some(session_state) = state.sessions.get_mut(&session) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        session_state.sign_key = Some(key);
        CKR_OK
    })
}

extern "C" fn c_sign(
    session: CK_SESSION_HANDLE,
    data: CK_BYTE_PTR,
    data_len: CK_ULONG,
    signature: CK_BYTE_PTR,
    signature_len: CK_ULONG_PTR,
) -> CK_RV {
    if signature_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    with_state(|state| {
        let Some(session_state) = state.sessions.get_mut(&session) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        let Some(key_handle) = session_state.sign_key else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };
        let Some((index, kind)) = resolve_handle(key_handle, &state.objects) else {
            return CKR_KEY_HANDLE_INVALID;
        };
        if kind != ObjectKind::Private {
            return CKR_KEY_HANDLE_INVALID;
        }
        let digest = if data_len == 0 {
            &[][..]
        } else {
            if data.is_null() {
                return CKR_ARGUMENTS_BAD;
            }
            unsafe { read_bytes(data as CK_VOID_PTR, data_len) }
        };
        let signed = match sign_with_tpm(&state.objects[index], digest) {
            Ok(bytes) => bytes,
            Err(_) => return CKR_FUNCTION_FAILED,
        };
        unsafe {
            if signature.is_null() {
                *signature_len = signed.len() as CK_ULONG;
                return CKR_OK;
            }
            if *signature_len < signed.len() as CK_ULONG {
                *signature_len = signed.len() as CK_ULONG;
                return CKR_BUFFER_TOO_SMALL;
            }
            ptr::copy_nonoverlapping(signed.as_ptr(), signature, signed.len());
            *signature_len = signed.len() as CK_ULONG;
        }
        CKR_OK
    })
}

extern "C" fn c_sign_update(
    _session: CK_SESSION_HANDLE,
    _part: CK_BYTE_PTR,
    _part_len: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn c_sign_final(
    _session: CK_SESSION_HANDLE,
    _signature: CK_BYTE_PTR,
    _signature_len: CK_ULONG_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

static FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION {
        major: 2,
        minor: 40,
    },
    C_Initialize: Some(c_initialize),
    C_Finalize: Some(c_finalize),
    C_GetInfo: Some(c_get_info),
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: Some(c_get_slot_list),
    C_GetSlotInfo: Some(c_get_slot_info),
    C_GetTokenInfo: Some(c_get_token_info),
    C_GetMechanismList: Some(c_get_mechanism_list),
    C_GetMechanismInfo: Some(c_get_mechanism_info),
    C_InitToken: None,
    C_InitPIN: None,
    C_SetPIN: None,
    C_OpenSession: Some(c_open_session),
    C_CloseSession: Some(c_close_session),
    C_CloseAllSessions: Some(c_close_all_sessions),
    C_GetSessionInfo: Some(c_get_session_info),
    C_GetOperationState: None,
    C_SetOperationState: None,
    C_Login: Some(c_login),
    C_Logout: Some(c_logout),
    C_CreateObject: None,
    C_CopyObject: None,
    C_DestroyObject: None,
    C_GetObjectSize: None,
    C_GetAttributeValue: Some(c_get_attribute_value),
    C_SetAttributeValue: None,
    C_FindObjectsInit: Some(c_find_objects_init),
    C_FindObjects: Some(c_find_objects),
    C_FindObjectsFinal: Some(c_find_objects_final),
    C_EncryptInit: None,
    C_Encrypt: None,
    C_EncryptUpdate: None,
    C_EncryptFinal: None,
    C_DecryptInit: None,
    C_Decrypt: None,
    C_DecryptUpdate: None,
    C_DecryptFinal: None,
    C_DigestInit: None,
    C_Digest: None,
    C_DigestUpdate: None,
    C_DigestKey: None,
    C_DigestFinal: None,
    C_SignInit: Some(c_sign_init),
    C_Sign: Some(c_sign),
    C_SignUpdate: Some(c_sign_update),
    C_SignFinal: Some(c_sign_final),
    C_SignRecoverInit: None,
    C_SignRecover: None,
    C_VerifyInit: None,
    C_Verify: None,
    C_VerifyUpdate: None,
    C_VerifyFinal: None,
    C_VerifyRecoverInit: None,
    C_VerifyRecover: None,
    C_DigestEncryptUpdate: None,
    C_DecryptDigestUpdate: None,
    C_SignEncryptUpdate: None,
    C_DecryptVerifyUpdate: None,
    C_GenerateKey: None,
    C_GenerateKeyPair: None,
    C_WrapKey: None,
    C_UnwrapKey: None,
    C_DeriveKey: None,
    C_SeedRandom: None,
    C_GenerateRandom: None,
    C_GetFunctionStatus: None,
    C_CancelFunction: None,
    C_WaitForSlotEvent: None,
};

#[unsafe(no_mangle)]
pub extern "C" fn C_GetFunctionList(function_list: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    if function_list.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        *function_list = &FUNCTION_LIST as *const CK_FUNCTION_LIST as CK_FUNCTION_LIST_PTR;
    }
    CKR_OK
}
