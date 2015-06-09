#![feature(libc, fs_ext, path_ext, convert, fs, exit_status)]
#![allow(dead_code)]

extern crate crypto;
extern crate libc;

#[macro_use]
extern crate log;
extern crate env_logger;

use crypto::sha2::Sha512;
use crypto::digest::Digest;
use libc::{getgid, getuid};
use std::env;
use std::path::Path;
use std::os::unix::fs::PermissionsExt;
use std::io;
use std::io::{Read, Write};
use std::fs::{File, Permissions, create_dir_all,
              set_permissions, PathExt};
use std::process::{Command, Stdio};

const ALL_PERMISSIONS: usize = 0o0777;
const OTHER_EXECUTE: usize = 0o0001;
const OTHER_READ: usize = 0o0004;
const OTHER_RWX: usize = 0o0007;
const GROUP_EXECUTE: usize = 0o0010;
const GROUP_READ: usize = 0o0040;
const GROUP_RWX: usize = 0o0070;
const USER_EXECUTE: usize = 0o0100;
const USER_READ: usize = 0o0400;
const USER_RWX: usize = 0o0700;

trait PermExt2 {
    fn contains(&self, mask: usize) -> bool;
}

impl PermExt2 for Permissions {
    fn contains(&self, mask: usize) -> bool {
        self.mode() & (mask as u32) != 0
    }
}

const CACHE_SUBPATH: &'static str = "pexe-runner-cache";
// TODO: support overriding cache location.
const CACHE_BASE: &'static str = "/tmp";

const RUST_PNACL_TRANS: &'static str = "rust_pnacl_trans";

fn mkdir<P: AsRef<Path>>(p: P, mode: usize) -> io::Result<()> {
    try!(create_dir_all(&p));
    chmod(p, mode)
}
fn chmod<P: AsRef<Path>>(p: P, mode: usize) -> io::Result<()> {
    let p = p.as_ref();
    let md = try!(p.metadata());
    let mut perms = md.permissions();
    perms.set_mode(mode as u32);
    set_permissions(p, perms)
}


pub fn main() {
    env_logger::init().unwrap();

    let args: Vec<String> = env::args()
        .collect();
    let pexe_path = Path::new(&(args[1])[..]);

    let cache = Path::new(CACHE_BASE).join(CACHE_SUBPATH);
    if !cache.exists() {
        mkdir(&cache, ALL_PERMISSIONS).unwrap();
    }

    // if the binary is rx by the world, don't use a user prefix when caching.

    let pexe = File::open(&pexe_path);
    if pexe.is_err() {
        panic!("could not open Pexe file!");
    }
    let mut pexe = pexe.unwrap();

    let pexe_filename = Path::new(pexe_path.file_name().unwrap());

    let pexe_stat = pexe.metadata().unwrap();
    let (cache_dir, perms) = if pexe_stat.permissions().contains(OTHER_EXECUTE | OTHER_READ) {
        let c = cache.join("other");
        if !c.exists() {
            mkdir(&c, ALL_PERMISSIONS).unwrap();
        }
        (c, ALL_PERMISSIONS)
    } else if pexe_stat.permissions().contains(GROUP_EXECUTE | GROUP_READ) {
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
    } else if pexe_stat.permissions().contains(USER_EXECUTE) {
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
    let mut pexe_bin = Vec::new();
    pexe.read_to_end(&mut pexe_bin)
        .unwrap();

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
        debug!("trans cmd line: `{:?}`", cmd);
        let trans = cmd.spawn().unwrap();

        let output = trans.wait_with_output().unwrap();
        let status = output.status;
        match status {
            _ if status.success() => {
                chmod(&nexe_path, perms).unwrap();
            }
            _ => {
                let mut stderr = ::std::io::stderr();
                let mut stdout = ::std::io::stdout();
                (writeln!(&mut stderr, "`{:?}` failed:", cmd)).unwrap();
                stdout.write(output.stdout.as_slice()).unwrap();
                stderr.write(output.stderr.as_slice()).unwrap();
                env::set_exit_status(status.code().unwrap_or(1));
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
                                "--reserved_at_zero=0xXXXXXXXXXXXXXXXX".to_string());
    match env::var("ALLOW_FILE_ACCESS") {
        Ok(ref v) if v != "0" => {
            sel_ldr_args.push("-a".to_string());
        },
        _ => {},
    }
    match env::var("DEBUG_PEXE") {
        Ok(ref v) if v != "0" => {
            sel_ldr_args.push("-g".to_string());
            println!("note: the nexe path is `{}`", nexe_path.display());
        },
        _ => {},
    }

    sel_ldr_args.push("-B".to_string());
    sel_ldr_args.push(irt_core.display().to_string());
    sel_ldr_args.push("-l".to_string());
    sel_ldr_args.push("/dev/null".to_string());
    sel_ldr_args.push("--".to_string());
    sel_ldr_args.push(nexe_path.display().to_string());
    for arg in &args[2..] {
        sel_ldr_args.push(arg.clone());
    }

    let mut cmd = Command::new(nacl_helper_bootstrap);
    cmd.args(sel_ldr_args.as_slice());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());
    debug!("sel_ldr cmd line: `{:?}`", cmd);
    match cmd.spawn() {
        Ok(mut process) => {
            match process.wait() {
                Ok(status) => {
                    env::set_exit_status(status.code().unwrap_or(1));
                },
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
