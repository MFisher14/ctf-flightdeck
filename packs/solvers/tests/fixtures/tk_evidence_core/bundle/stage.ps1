# stage.ps1 (test fixture, does nothing harmful)
# build id c47ea6baee51aaed1d824b0cf5e3086c1b7581a9404a8c37d8f8cc6baa887113
$next = 'hxxp://cdn[.]update-check[.]example/payload.bin'
$drop = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('aHR0cHM6Ly9leGZpbC5zdGFnaW5nLWRyb3AuZXhhbXBsZS91cGxvYWQ/aWQ9Nw=='))
Write-Output "fixture: $next $drop"
