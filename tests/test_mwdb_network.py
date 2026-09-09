"""MWDB scan URLs and safe API diagnostics; also runnable without Qt."""
import io
import json
import ssl
import unittest
from urllib.error import HTTPError, URLError

from yaraxgui.network import api_error_message, mwdb_api_url


class MwdbScanNetworkTests(unittest.TestCase):
    def test_supported_input_urls_select_the_same_allowed_destination(self):
        expected = 'https://192.168.50.12:8443/api'
        for suffix in ('', '/', '/api', '/api/', '/api///'):
            with self.subTest(suffix=suffix):
                self.assertEqual(mwdb_api_url('  https://192.168.50.12:8443' + suffix + '  '), expected)

    def test_mwdb_path_prefix_is_preserved(self):
        self.assertEqual(mwdb_api_url('https://example.test/mwdb/api/'),
                         'https://example.test/mwdb/api')

    def test_invalid_or_insecure_scan_destinations_are_rejected(self):
        for value in ('', 'http://localhost:8080/api', 'file:///tmp/api',
                      'https://user:password@example.test/api',
                      'https://example.test/api?token=secret',
                      'https://example.test/api#fragment',
                      'https://example.test:bad/api'):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    mwdb_api_url(value)

    def message(self, detail, code=403, url='https://192.168.50.12/scan/mwdb'):
        stream = io.BytesIO(json.dumps({'detail': detail}).encode())
        error = HTTPError(url, code, 'Forbidden', {}, stream)
        result = api_error_message(error, url)
        self.assertTrue(stream.closed)
        return result

    def test_api_key_failure_identifies_the_scan_server_credentials(self):
        message = self.message('Invalid API key')
        self.assertIn('https://192.168.50.12:443', message)
        self.assertIn('YaraXGUI API key is missing or incorrect', message)
        self.assertNotIn('YARAXGUI_MWDB_URL', message)

    def test_destination_failure_identifies_server_configuration(self):
        message = self.message('MWDB scans require the server-configured YARAXGUI_MWDB_URL')
        self.assertIn('YARAXGUI_MWDB_URL', message)
        self.assertIn('recreate the API container', message)
        self.assertNotIn('key is missing or incorrect', message)

    def test_unrecognized_refusal_shows_the_configured_endpoint_without_secrets(self):
        message = self.message('<b>private-token</b>',
                               url='https://user:private-password@192.168.50.12:8443/scan/mwdb?key=private-query')
        self.assertIn('https://192.168.50.12:8443', message)
        self.assertIn('Check YaraXGUI Server and API Key', message)
        for secret in ('private-token', 'private-password', 'private-query', '/scan/mwdb', '<b>'):
            self.assertNotIn(secret, message)

    def test_malformed_and_large_error_responses_use_a_safe_fallback(self):
        for body in (b'<html>Forbidden</html>', b'[]',
                     json.dumps({'detail': 'private-token' * 1000}).encode()):
            with self.subTest(size=len(body)):
                stream = io.BytesIO(body)
                error = HTTPError('https://example.test', 403, 'private-reason', {}, stream)
                message = api_error_message(error, 'https://example.test')
                self.assertIn('HTTP 403', message)
                self.assertNotIn('private-', message)
                self.assertTrue(stream.closed)

    def test_tls_failure_remains_a_certificate_diagnostic(self):
        message = api_error_message(URLError(ssl.SSLCertVerificationError('untrusted')),
                                    'https://192.168.50.12')
        self.assertIn('TLS certificate verification failed', message)
        self.assertIn('Additional CA (PEM)', message)
        self.assertNotIn('HTTP 403', message)


if __name__ == '__main__':
    unittest.main()
