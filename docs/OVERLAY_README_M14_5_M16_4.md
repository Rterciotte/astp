# ASTP M14.5-M16.4 overlay

Apply this archive over the validated M12.7-M14.4 tree. Release notes live in `docs/release/`. This overlay does not relocate existing documentation files.

Validation order:

```powershell
.\scripts\validate.ps1
.\scripts\field-tests\m14.5-m16.4.ps1
```

Do not commit until both pass.
