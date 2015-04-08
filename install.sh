#!/bin/sh

(cargo build --release &&
    echo "Copying bin to /usr/local/bin (prepare for sudo):" &&
    sudo rm -f /usr/local/bin/pexe-runner &&
    sudo cp target/release/pexe_runner /usr/local/bin/ &&
    echo "Done!") || exit 1;

if [ -f /proc/sys/fs/binfmt_misc/pnacl ]; then
    (sudo sh -c 'echo "-1" > /proc/sys/fs/binfmt_misc/pnacl') || exit 1;
fi
(sudo sh -c 'echo ":pnacl:E::pexe::/usr/local/bin/pexe_runner:" > /proc/sys/fs/binfmt_misc/register') || exit 1;

echo "Good to go! You can now use pexes wherever you use regular binaries."
