
#![feature(phase)]

extern crate crypto;
extern crate libc;
#[phase(plugin, link)] extern crate log;

use crypto::sha2::Sha512;
use crypto::digest::Digest;
use libc::{getgid, getuid};
use std::os;
use std::io::{OTHER_EXECUTE, OTHER_READ,
              GROUP_EXECUTE, GROUP_READ, GROUP_RWX,
              USER_EXECUTE,  USER_RWX, ALL_PERMISSIONS};
use std::io::fs::{File, PathExtensions, mkdir, mkdir_recursive, chmod};
use std::io::process::{Command, InheritFd, ExitStatus, ExitSignal};

const CACHE_SUBPATH: &'static str = "pexe-runner-cache";
// TODO: support overriding cache location.
const CACHE_BASE: &'static str = "/tmp";

const RUST_PNACL_TRANS: &'static str = "rust-pnacl-trans";

pub fn main() {
    let args = os::args();
    if args.len() != 2 { return; }
    let pexe_path = Path::new(args[1].as_slice());
    let pexe_filename = Path::new(pexe_path.filename().unwrap());

    let cache = Path::new(CACHE_BASE).join(CACHE_SUBPATH);
    if !cache.exists() {
        mkdir_recursive(&cache, ALL_PERMISSIONS).unwrap();
    }

    // if the binary is rx by the world, don't use a user prefix when caching.

    let mut pexe = File::open(&pexe_path).unwrap();

    let pexe_stat = pexe.stat().unwrap();
    let (cache_dir, perms) = if pexe_stat.perm.contains(OTHER_EXECUTE | OTHER_READ) {
        let c = cache.join("other");
        if !c.exists() {
            mkdir(&c, ALL_PERMISSIONS).unwrap();
        }
        (c, ALL_PERMISSIONS)
    } else if pexe_stat.perm.contains(GROUP_EXECUTE | GROUP_READ) {
        let c = cache.join("group");
        if !c.exists() {
            mkdir(&c, ALL_PERMISSIONS).unwrap();
        }
        let gid = unsafe { getgid() };
        let c = c.join(format!("{}", gid));
        if !c.exists() {
            mkdir(&c, GROUP_RWX | USER_RWX).unwrap();
        }
        (c, GROUP_RWX | USER_RWX)
    } else if pexe_stat.perm.contains(USER_EXECUTE) {
        let c = cache.join("user");
        if !c.exists() {
            mkdir(&c, ALL_PERMISSIONS).unwrap();
        }
        let uid = unsafe { getuid() };
        let c = c.join(format!("{}", uid));
        if !c.exists() {
            mkdir(&c, USER_RWX).unwrap();
        }
        (c, USER_RWX)
    } else {
        panic!("cann't execute: permissing denied");
    };

    let pexe_bin = pexe.read_to_end().unwrap();

    let mut hasher = Sha512::new();
    hasher.input(pexe_bin.as_slice());
    let cache_dir = cache_dir.join(hasher.result_str());
    if !cache_dir.exists() {
        mkdir(&cache_dir, perms).unwrap();
    }
    let nexe_path = cache_dir
        .join(pexe_filename.with_extension("nexe"));

    let nacl_sdk_root = env!("NACL_SDK_ROOT");

    if !nexe_path.exists() {
        let mut cmd = Command::new(RUST_PNACL_TRANS);
        cmd.arg("--cross-path");
        cmd.arg(nacl_sdk_root);
        cmd.arg(pexe_path.display().to_string());
        cmd.arg("-o");
        cmd.arg(nexe_path.display().to_string());
        cmd.arg("--opt-level=2");
        debug!("trans cmd line: `{}`", cmd);
        let mut trans = cmd.spawn().unwrap();

        let output = trans.wait_with_output().unwrap();
        let status = output.status;
        match status {
            ExitStatus(0) => {
                chmod(&nexe_path, perms).unwrap();
            }
            ExitStatus(code) | ExitSignal(code) => {
                let mut stderr = ::std::io::stdio::stderr();
                let mut stdout = ::std::io::stdio::stdout();
                writeln!(stderr, "`{}` failed:", cmd);
                stdout.write(output.output.as_slice()).unwrap();
                stderr.write(output.error.as_slice()).unwrap();
                os::set_exit_status(code);
                return;
            }
        }
    }

    let nacl_sdk_root = Path::new(nacl_sdk_root);
    let tools = nacl_sdk_root.join("tools");
    let nacl_helper_bootstrap = tools.join("nacl_helper_bootstrap_x86_64");
    let sel_ldr_bin = tools.join("sel_ldr_x86_64");
    let irt_core = tools.join("irt_core_x86_64.nexe");

    let mut sel_ldr_args = vec!(sel_ldr_bin.display().to_string(),
                                "--r_debug=0xXXXXXXXXXXXXXXXX".to_string(),
                                "--reserved_at_zero=0xXXXXXXXXXXXXXXXX".to_string(),
                                //"-a".to_string(),
                                "-B".to_string(),
                                irt_core.display().to_string(),
                                "-l".to_string(), "/dev/null".to_string());
    sel_ldr_args.push("--".to_string());
    sel_ldr_args.push(nexe_path.display().to_string());
    sel_ldr_args.extend(args.slice_from(2).to_vec().into_iter());

    let mut cmd = Command::new(nacl_helper_bootstrap);
    cmd.args(sel_ldr_args.as_slice());
    cmd.stdout(InheritFd(libc::STDOUT_FILENO));
    cmd.stderr(InheritFd(libc::STDERR_FILENO));
    debug!("sel_ldr cmd line: `{}`", cmd);
    match cmd.spawn() {
        Ok(mut process) => {
            match process.wait() {
                Ok(ExitStatus(status)) => {
                    os::set_exit_status(status);
                }
                Ok(_) => {
                    os::set_exit_status(1);
                }
                Err(e) => {
                    panic!("couldn't wait on sel_ldr: {}", e);
                }
            }
        }
        Err(e) => {
            panic!("couldn't spawn sel_ldr: {}", e);
        }
    }
}
