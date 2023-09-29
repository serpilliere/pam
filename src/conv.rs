use libc::{c_int, c_void, calloc, free, size_t, strdup};
use std::os::raw::{c_char};
use std::ffi::{CStr, CString};
use std::{ptr::null_mut};

use std::mem;

use crate::{ffi::pam_conv, PamMessage, PamMessageStyle, PamResponse, PamReturnCode};

const test_str: &[i8] = &[0x31, 0x32, 0x0];


/// A trait representing the PAM authentification conversation
///
/// PAM authentification is done as a conversation mechanism, in which PAM
/// asks several questions and the client (your code) answers them. This trait
/// is a representation of such a conversation, which one method for each message
/// PAM can send you.
///
/// This is the trait to implement if you want to customize the conversation with
/// PAM. If you just want a simple login/password authentication, you can use the
/// `PasswordConv` implementation provided by this crate.
pub trait Conversation {
    /// PAM requests a value that should be echoed to the user as they type it
    ///
    /// This would typically be the username. The exact question is provided as the
    /// `msg` argument if you wish to display it to your user.
    fn prompt_echo(&mut self, msg: &CStr) -> Result<CString, ()>;
    /// PAM requests a value that should be typed blindly by the user
    ///
    /// This would typically be the password. The exact question is provided as the
    /// `msg` argument if you wish to display it to your user.
    fn prompt_blind(&mut self, msg: &CStr) -> Result<CString, ()>;
    /// This is an informational message from PAM
    fn info(&mut self, msg: &CStr);
    /// This is an error message from PAM
    fn error(&mut self, msg: &CStr);
}

/// A minimalistic conversation handler, that uses given login and password
///
/// This conversation handler is not really interactive, but simply returns to
/// PAM the value that have been set using the `set_credentials` method.
pub struct PasswordConv {
    login: String,
    passwd: String,
}

impl PasswordConv {
    /// Create a new `PasswordConv` handler
    pub(crate) fn new() -> PasswordConv {
        PasswordConv {
            login: String::new(),
            passwd: String::new(),
        }
    }

    /// Set the credentials that this handler will provide to PAM
    pub fn set_credentials<U: Into<String>, V: Into<String>>(&mut self, login: U, password: V) {
        self.login = login.into();
        self.passwd = password.into();
    }
}

impl Conversation for PasswordConv {
    fn prompt_echo(&mut self, _msg: &CStr) -> Result<CString, ()> {
        CString::new(self.login.clone()).map_err(|_| ())
    }
    fn prompt_blind(&mut self, _msg: &CStr) -> Result<CString, ()> {
        CString::new(self.passwd.clone()).map_err(|_| ())
    }
    fn info(&mut self, _msg: &CStr) {}
    fn error(&mut self, msg: &CStr) {
        eprintln!("[PAM ERROR] {}", msg.to_string_lossy());
    }
}

pub(crate) fn into_pam_conv<C: Conversation>(conv: &mut C) -> pam_conv {
    pam_conv {
        conv: Some(converse::<C>),
        appdata_ptr: conv as *mut C as *mut c_void,
    }
}

// FIXME: verify this
pub(crate) unsafe extern "C" fn converse<C: Conversation>(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    out_resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
) -> c_int {
    // DBG

    println!("skip");

    println!("Alloc");
    // allocate space for responses
    let resp =
        calloc(num_msg as usize, mem::size_of::<PamResponse>() as size_t) as *mut PamResponse;
    if resp.is_null() {
        return PamReturnCode::Buf_Err as c_int;
    }
    *out_resp = resp;
    for i in 0..num_msg as isize {
        let r: &mut PamResponse = &mut *(resp.offset(i));
        r.resp = strdup(test_str.as_ptr());
        println!("resp {:?}", r.resp);
    }
    println!("Messages: {:?}", num_msg);
    let mut result: PamReturnCode = PamReturnCode::Success;
    return result as c_int;
    for i in 0..num_msg as isize {
        // get indexed values
        // FIXME: check this
        let m: &PamMessage = match (*(msg.offset(i))).as_ref() {
            Some(pam_message) => pam_message,
            None => {
                println!("null message");
                return 0;
            }
        };
        let r: &mut PamResponse = &mut *(resp.offset(i));

        let msg = CStr::from_ptr(m.msg);
        // match on msg_style
        match PamMessageStyle::from(m.msg_style) {
            PamMessageStyle::Prompt_Echo_On => {
                println!("{} - echo on", i);
                /*
                if let Ok(handler_response) = handler.prompt_echo(msg) {
                    r.resp = strdup(handler_response.as_ptr());
                } else {
                    result = PamReturnCode::Conv_Err;
                }
                 */
                let c_str = CString::new("test").unwrap();
                let c_world: *const c_char = c_str.as_ptr() as *const c_char;
                r.resp = strdup(c_world);
            }
            PamMessageStyle::Prompt_Echo_Off => {
                println!("{} - echo off", i);
                /*
                if let Ok(handler_response) = handler.prompt_blind(msg) {
                    r.resp = strdup(handler_response.as_ptr());
                } else {
                    result = PamReturnCode::Conv_Err;
                }
                 */
                let c_str = CString::new("test").unwrap();
                let c_world: *const c_char = c_str.as_ptr() as *const c_char;
                r.resp = strdup(c_world);

            }
            PamMessageStyle::Text_Info => {
                println!("{} - text info", i);
                //handler.info(msg);
                println!("info {:?}", msg);
            }
            PamMessageStyle::Error_Msg => {
                println!("{} - error info", i);
                /*
                handler.error(msg);
                */
                println!("err {:?}", msg);

                result = PamReturnCode::Conv_Err;
            }
        }
        if result != PamReturnCode::Success {
            break;
        }
    }

    println!("result {:?} ", result);

    // free allocated memory if an error occured
    if result != PamReturnCode::Success {
        println!("free");
        free(resp as *mut c_void);
        println!("free done");
        // XXX TOTO free sub msgs
        *out_resp = null_mut();
    } else {
        *out_resp = resp;
    }

    result as c_int
}
