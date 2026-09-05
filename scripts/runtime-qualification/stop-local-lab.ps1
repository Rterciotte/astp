$ErrorActionPreference = "Continue"
docker rm -f astp-qualification-lab *> $null
docker network rm astp-qualification-net *> $null
Write-Host "Qualification lab stopped and isolated network removed."
