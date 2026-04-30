"""Static defaults used by UploadBuster."""

DEFAULT_CONFIG_PATH = "data/config.json"
DEFAULT_PAYLOAD_PATH = "PAYLOAD.php"
DEFAULT_SUCCESS_MESSAGE = "success"
DEFAULT_FORM_DATA = "submit,Upload"
DEFAULT_UPLOAD_FIELD = "file"
DEFAULT_TIMEOUT = 3.0
DEFAULT_DELAY = 0.5
DEFAULT_RETRIES = 2
DEFAULT_MAX_REQUESTS = 1000
DEFAULT_CONTENT_TYPE = "application/octet-stream"
PHP_HELLO_PAYLOAD = b'<?php echo "HelloWorld";?>'
PHP_SHORT_PAYLOAD = b"<?=`$_GET[x]`?>"
