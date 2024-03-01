from contextlib import contextmanager
import os
import subprocess
from pathlib import Path
import sys


def getProjectRoot() -> Path:
    return Path(__file__).parent.parent.parent


@contextmanager
def cd(path):
    old_cwd = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(old_cwd)


def sh(command):
    try:
        if isinstance(command, list):
            command = " ".join(command)
        p = subprocess.run(
            command,
            shell=True,
        )
        return p.returncode
    except subprocess.CalledProcessError as e:
        return e.returncode


def useDocker(file: str):
    if os.getenv("SEEDEMU_INSIDE_DOCKER") == "True":
        return
    else:
        root = getProjectRoot()
        with cd(root):
            code = sh(
                "docker build -t seedemu/seedemu:latest --build-arg UID=$(id -u) --build-arg GID=$(id -g) ."
            )
            if code != 0:
                exit(code)
        rel_cwd = os.path.relpath(os.getcwd(), root)
        rel_file = os.path.relpath(file, os.getcwd())
        argv=" ".join(sys.argv[1:])
        code = sh(
            f"docker run --rm -v {root}:/home/ubuntu/seed-emulator -w /home/ubuntu/seed-emulator/{rel_cwd} --entrypoint python3 seedemu/seedemu {rel_file} {argv}"
        )
        exit(code)
