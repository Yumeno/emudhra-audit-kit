import io
import ssl
import unittest
from unittest.mock import patch
import urllib.error
import probe_python as probe
import audit_summary


class Tests(unittest.TestCase):
    def cert_error(self, code):
        error = ssl.SSLCertVerificationError('test fixture')
        error.verify_code = code
        return error

    def test_unknown_issuer(self):
        self.assertEqual(probe.classify_exception(self.cert_error(20))[0], 'REJECT')

    def test_cert_rejected(self):
        # Some CPython builds reject the base route with verify_code 28 (X509_V_ERR_CERT_REJECTED).
        self.assertEqual(probe.classify_exception(self.cert_error(28))[0], 'REJECT')

    def test_expired(self):
        self.assertEqual(probe.classify_exception(self.cert_error(10))[0], 'UNKNOWN')

    def test_truststore_windows_codes(self):
        # truststore on Windows puts the HRESULT in verify_code, e.g. 2148081680 (CRYPT_E_REVOKED).
        self.assertEqual(probe.classify_exception(self.cert_error(0x80092010))[0], 'REJECT')
        self.assertEqual(probe.classify_exception(self.cert_error(0x800B0111 - 0x100000000))[0], 'REJECT')
        self.assertEqual(probe.classify_exception(self.cert_error(0x800B0101))[0], 'UNKNOWN')   # CERT_E_EXPIRED
        self.assertEqual(probe.classify_exception(self.cert_error(0x800B010F))[0], 'UNKNOWN')   # CERT_E_CN_NO_MATCH

    def test_generic_tls(self):
        self.assertEqual(probe.classify_exception(ssl.SSLError('SSL revoked words alone'))[0], 'UNKNOWN')

    def test_nested(self):
        error = Exception(Exception(self.cert_error(20)))
        self.assertEqual(probe.classify_exception(error)[0], 'REJECT')

    def test_mixed(self):
        error = Exception(self.cert_error(20), self.cert_error(10))
        self.assertEqual(probe.classify_exception(error)[0], 'UNKNOWN')

    def test_context_failure(self):
        with patch.object(probe.ssl, 'create_default_context', side_effect=FileNotFoundError()):
            self.assertEqual(probe.urllib_probe('https://example.test/')[0], 'UNKNOWN')

    def http_error_result(self, code, body):
        class Opener:
            def open(self, *args, **kwargs):
                raise urllib.error.HTTPError('https://example.test/', code, 'fixture', {}, body)
        with patch.object(probe.urllib.request, 'build_opener', return_value=Opener()):
            return probe.urllib_probe('https://example.test/')

    def test_http403(self):
        # A real urllib HTTPError carries the response body.
        self.assertEqual(self.http_error_result(403, io.BytesIO(b'')), ('ACCEPT', 'http=403'))

    def test_http403_without_body(self):
        # Python 3.9 raises KeyError from close() when the body is None; the verdict stays ACCEPT.
        self.assertEqual(self.http_error_result(403, None), ('ACCEPT', 'http=403'))

    def test_http407_is_unknown(self):
        self.assertEqual(self.http_error_result(407, io.BytesIO(b''))[0], 'UNKNOWN')

    def test_import_broken(self):
        with patch.object(probe.importlib, 'import_module', side_effect=ImportError('broken')):
            self.assertEqual(probe.optional_module('certifi')[1][0], 'UNKNOWN')

    def test_timeout_unknown(self):
        self.assertEqual(probe.classify_exception(TimeoutError())[0], 'UNKNOWN')


class SummaryTests(unittest.TestCase):
    # audit_summary.summarize must match Get-AuditSummary (Test-Helpers.ps1 has the same cases).
    def status(self, rows):
        return audit_summary.summarize([(t, g, v, '') for t, g, v in rows], 'control', ['a', 'b'])[0][1]

    def test_fixed(self):
        self.assertEqual(self.status([('x', 'control', 'ACCEPT'), ('x', 'a', 'REJECT'), ('x', 'b', 'REJECT')]), 'FIXED')

    def test_control_unknown_target_accepted(self):
        # v2.11.5: old uv cannot prove the control request.
        self.assertEqual(self.status([('x', 'control', 'UNKNOWN'), ('x', 'a', 'ACCEPT'), ('x', 'b', 'REJECT')]), 'VULNERABLE')

    def test_control_unknown_never_fixed(self):
        rows = [('x', 'control', 'UNKNOWN', ''), ('x', 'a', 'REJECT', ''), ('x', 'b', 'REJECT', '')]
        self.assertEqual(audit_summary.summarize(rows, 'control', ['a', 'b'])[0][1:],
                         ('UNKNOWN', 'Control missing, duplicated, or not ACCEPT.'))

    def test_control_reject_or_missing(self):
        self.assertEqual(self.status([('x', 'control', 'REJECT'), ('x', 'a', 'ACCEPT'), ('x', 'b', 'REJECT')]), 'UNKNOWN')
        self.assertEqual(self.status([('x', 'control', 'NONE'), ('x', 'a', 'ACCEPT'), ('x', 'b', 'REJECT')]), 'UNKNOWN')
        self.assertEqual(self.status([('x', 'a', 'ACCEPT'), ('x', 'b', 'REJECT')]), 'UNKNOWN')

    def test_control_unknown_incomplete(self):
        self.assertEqual(self.status([('x', 'control', 'UNKNOWN'), ('x', 'control', 'UNKNOWN'),
                                      ('x', 'a', 'ACCEPT'), ('x', 'b', 'ACCEPT')]), 'UNKNOWN')
        self.assertEqual(self.status([('x', 'control', 'UNKNOWN'), ('x', 'a', 'ACCEPT'),
                                      ('x', 'a', 'ACCEPT'), ('x', 'b', 'REJECT')]), 'UNKNOWN')
        self.assertEqual(self.status([('x', 'control', 'UNKNOWN'), ('x', 'a', 'ACCEPT')]), 'UNKNOWN')


if __name__ == '__main__':
    unittest.main()
