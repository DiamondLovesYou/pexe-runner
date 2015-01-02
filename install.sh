#!/bin/sh

cargo build --release && sudo cp target/release/pexe-runner /usr/local/bin/ && sudo sh -c 'echo ":pnacl:E::pexe::/usr/local/bin/pexe-runner:" > /proc/sys/fs/binfmt_misc/register' && echo "Good to go! You can now use pexes wherever you use regular binaries."
