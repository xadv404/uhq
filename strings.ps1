$bytes = [System.IO.File]::ReadAllBytes($args[0])
$text = [System.Text.Encoding]::ASCII.GetString($bytes)

# Find all URLs
$urlPattern = '(https?://[a-zA-Z0-9_./:@\-?=&]+)'
$urls = [regex]::Matches($text, $urlPattern) | ForEach-Object { $_.Value } | Sort-Object -Unique

# Find discord/webhook related
$discordPattern = '(discord|webhook|api\.gg|gofile)[a-zA-Z0-9_./:@\-?=&]*'
$discordStrings = [regex]::Matches($text, $discordPattern) | ForEach-Object { $_.Value } | Sort-Object -Unique

Write-Host "=== URLs FOUND ==="
$urls | Select-Object -First 30

Write-Host "`n=== DISCORD/WEBHOOK STRINGS ==="
$discordStrings | Select-Object -First 30
