import unittest

from uploadbuster.payloads import PayloadFactory


class PayloadFactoryTests(unittest.TestCase):
    def test_create_payload_builds_full_filename(self):
        factory = PayloadFactory(upload_field_name="file", base_data=b"hello")

        payload = factory.create(".php", filename="sample", mutate_extension_case=False)

        self.assertEqual(payload.full_filename, "sample.php")
        self.assertEqual(payload.upload_field_name, "file")
        self.assertEqual(payload.data, b"hello")

    def test_multi_extension_uses_allowed_extension_first(self):
        factory = PayloadFactory(upload_field_name="file", base_data=b"hello")

        payload = factory.multi_extension(".php", "jpg", 2)

        self.assertTrue(payload.full_filename.lower().endswith(".jpg.php.php"))

    def test_magic_bytes_are_prepended(self):
        factory = PayloadFactory(upload_field_name="file", base_data=b"<?php")

        payload = factory.with_magic_bytes(".php", "ffd8ff")

        self.assertTrue(payload.data.startswith(bytes.fromhex("ffd8ff")))
        self.assertIn(b"<?php", payload.data)


if __name__ == "__main__":
    unittest.main()
