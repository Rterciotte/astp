$ErrorActionPreference = "Stop"
Write-Host "ASTP M46.7a ASSESSMENT AUTONOMY HARDENING"
python -m pytest .\tests\test_m467a_assessment_autonomy_hardening.py -q
Write-Host "Network execution: NOT PERFORMED"
