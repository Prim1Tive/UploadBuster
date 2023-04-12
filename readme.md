# UploadBuster - Bust upload file restrictions.

UploadBuster Was created to help Security Researchers locate unrestricted file upload vulnerabilities. Prim1Tive™

## Requierments:

- python3

## Installation:
- $ pip install requests
- $ git clone https://github.com/Prim1Tive/UploadBuster.git

## Usage:
```
   __  __      __                ______
  / / / /___  / /___  ____ _____/ / __ )__  _______/ /____  _____
 / / / / __ \/ / __ \/ __ `/ __  / __  / / / / ___/ __/ _ \/ ___/
/ /_/ / /_/ / / /_/ / /_/ / /_/ / /_/ / /_/ (__  ) /_/  __/ /
\____/ .___/_/\____/\__,_/\__,_/_____/\__,_/____/\__/\___/_/
    /_/


usage: UploadBuster [-h] -u  -b  -e  [-a] [-p] [-s] [-d] [-uv] [-c] [-i] [-to] [-re] [-be] [-bn] [-bc] [-bm] [-bl] [-te] [-db] [-vi] [-vo] [-v] [-vs]

UploadBuster Was created to help Security Researchers locate unrestricted file upload vulnerabilities. Prim1Tive™

options:
  -h, --help            show this help message and exit
  -u , --url            Full url to the upload script [http://example.local/upload.php]
  -b , --backend        The backend language of the website [php,jsp,asp]
  -e , --extensions     Allowed extensions for the upload form [jpeg,docx,png,pdf, please put only one.]
  -p , --payload        Payload to sent, default: the preferred language hello script if not provided the script will be <?php echo HelloWorld;?>
  -s , --success-message
                        The success string of the upload script. [Upload was successful! uploads/image.jpg]
  -d , --data           Add custom data to the request [name,key]
  -uv , --upload-variable
                        main page upload php form variable (i.e form-data; name:###
  -c , --headers        Add custom headers to the request
  -i , --intervals      Add a delay between requests.
  -to , --request-time-out
                        Add a delay between requests.
  -re, --request-redirects
                        Request Redirects flag.

Tests:
  -a, --all-tests       Run all avilable tests
  -be, --bruteforce-extension
                        Extension Brute forcing.
  -bn, --bruteforce-null-extension
                        Null Extension Brute forcing.
  -bc, --bruteforce-content-type
                        Content-Type field Brute forcing.
  -bm , --bruteforce-multi-extension
                        Tries to brute force using double extension technique. can add the number of times to inject the extensions. (-de [3] = jpg.php.php.php)
  -bl, --bruteforce-filename-limit
                        Content-Type field Brute forcing.
  -te, --tech-execution-extension
                        Try to edit .htaccess so it would treat extension as a php file extension.
  -db, --dont-brute     if success message is found stop all tests.
  -vi, --print-i        print the Request
  -vo, --print-o        print the Response
  -v, --print           full data of the request
  -vs, --verbal-success
                        Turn off success message [switch]


legal disclaimer:
Usage of UploadBuster for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible fo
r any misuse or damage caused by this program.

```

## Example:
```
 python3 UploadBuster.py -u http://localhost:9001/upload1/index.php -b php -e jpeg -uv fileToUpload -d submit,Upload -s "The file has been uploaded here" -a -v -i 1 -p payload.php

-b = backend
-e = allowed extensions
-a = all tests
-v = Verbose
-i = requests per-second
-p = payload file name
-s = success string
-uv = file variable of the html page.
```

## Verbose message:
```
[+] Success message found!
> Payload:                                                                                                                                          
        > URL: http://localhost/upload1/index.php                                                                                              
        + ~~~~~~~~~~~~~~~~~~~~~~~~~~                                                                                                                
        > HEADERS: {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36'}
        + ~~~~~~~~~~~~~~~~~~~~~~~~~~                                                                                                                
        > FILE: {'fileToUpload': ('fd09b.phtml', b'<?php echo HelloWorld;?>', '')}                                                                  
        + ~~~~~~~~~~~~~~~~~~~~~~~~~~                                                                                                                
        > DATA: {'submit': 'Upload'}
        + ~~~~~~~~~~~~~~~~~~~~~~~~~~
        > SUCCESS LINE: <p class="alert-success">the file has been uploaded here: <a href="uploads/fd09b.phtml">uploads/fd09b.phtml</a>.</p>    <script type="text/javascript" src="../static/css/bootstrap.min.js"></script>
```
