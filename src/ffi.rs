use std::os::raw::c_char;

extern "C" {
    pub fn initialize_telemetry_engine(
        bpf_obj_path: *const c_char,
        socket_path: *const c_char,
        auth_token: *const c_char,
    ) -> bool;

    pub fn start_telemetry_engine() -> bool;

    pub fn stop_telemetry_engine();

    pub fn add_sensitive_inode(inode: u64, category: u32) -> bool;
    pub fn is_lsm_active() -> bool;
}
