# Windows 11 development setup

Windows 11 is a suitable host for ASTP. We will not require every security utility to
run natively on Windows.

## Recommended layers

### Native Windows

Use VS Code, Git, Python, the frontend toolchain and normal project commands here.

### WSL2

WSL2 supplies a real Linux kernel environment on Windows and is the compatibility layer for
Linux-oriented development and tooling.

Suggested setup from an elevated PowerShell if WSL is not installed:

```powershell
wsl --install
```

After restart:

```powershell
wsl --update
wsl --status
wsl --list --verbose
```

### Docker Desktop

Use the WSL2 backend and Linux containers. Future scanners will run in isolated workers with
CPU, memory, timeout, network and filesystem restrictions.

## Repository location

For Milestone 0, keeping the repository on your normal Windows development drive is fine.
When Linux-container bind-mount performance becomes important, we can decide whether a
worker workspace should live inside the WSL filesystem.

## VS Code

The same repository can be opened normally on Windows. When we later need Linux-native
work, VS Code can also open the project or a worker workspace through WSL.

## Do not install Kali as the project foundation

A pentest distribution can be useful as a disposable laboratory, but ASTP should depend
on explicit container images and versions, not on an opaque workstation containing hundreds
of globally installed tools.
