# UploadBuster - Bust upload file restrictions.

UploadBuster Was created by Michael Azoulay to help Security Researchers locate unrestricted file upload vulnerabilities.


## Requierments:

- python3

## Installation:
- $ pip install requests
- $ git clone https://github.com/Prim1Tive/UploadBuster.git

## Usage:
```
usage: python3 UploadBuster.py [-h] -u URL -b BACKEND -e EXTENSIONS [-a] [-p PAYLOAD] [-s SUCCESS_MESSAGE] [-d DATA] [-uv UPLOAD_VARIABLE] [-c HEADERS] [-i INTERVALS] [-to REQUEST_TIME_OUT] [-re] [-be] [-bn] [-bc]
                    [-de BRUTEFORCE_MULTI_EXTENSION] [-bl] [-db] [-vi] [-vo] [-v] [-vs]
                    
  -h, --help            show this help message and exit
  -u URL, --url URL     Full url to the upload script [http://example.local/upload.php]
  -b BACKEND, --backend BACKEND
                        The backend language of the website [php,jsp,asp]
  -e EXTENSIONS, --extensions EXTENSIONS
                        Allowed extensions for the upload form [jpeg,docx,png,pdf, please put only one.]
  -a, --all-tests       Make the full test of insecure file upload on target
  -p PAYLOAD, --payload PAYLOAD
                        Payload to sent, default: the preferred language hello script if not provided the script will be <?php echo HelloWorld;?>
  -s SUCCESS_MESSAGE, --success-message SUCCESS_MESSAGE
                        The success string of the upload script. [Upload was successful! uploads/image.jpg]
  -d DATA, --data DATA  Add custom data to the request [name,key]
  -uv UPLOAD_VARIABLE, --upload-variable UPLOAD_VARIABLE
                        main page upload php form variable (i.e form-data; name:###
  -c HEADERS, --headers HEADERS
                        Add custom headers to the request
  -i INTERVALS, --intervals INTERVALS
                        Add a delay between requests.
  -to REQUEST_TIME_OUT, --request-time-out REQUEST_TIME_OUT
                        Add a delay between requests.
  -re, --request-redirects
                        Request Redirects flag.
  -be, --bruteforce-extension
                        Extension Brute forcing.
  -bn, --bruteforce-null-extension
                        Null Extension Brute forcing.
  -bc, --bruteforce-content-type
                        Content-Type field Brute forcing.
  -de BRUTEFORCE_MULTI_EXTENSION, --bruteforce-multi-extension BRUTEFORCE_MULTI_EXTENSION
                        Tries to brute force using double extension technique. can add the number of times to inject the extensions. (-de [3] = jpg.php.php.php)
  -bl, --bruteforce-filename-limit
                        Content-Type field Brute forcing.
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
