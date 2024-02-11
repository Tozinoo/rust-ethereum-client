// extern crate mdbx_sys;
// use std::ffi::CString;
// use mdbx_sys::*;
// pub fn mdbx_test() {
//     unsafe {
//         let path = CString::new("/path/to/your/database").unwrap();
//         let mut env = std::ptr::null_mut();
//         mdbx_env_create(&mut env);
//         mdbx_env_open(env, path.as_ptr(), MDBX_env_flags_t::MDBX_NOSUBDIR, 0o644);
//         // 데이터베이스와 관련된 작업 수행
//         mdbx_env_close(env);
//     }
//     println!("test");
// }
