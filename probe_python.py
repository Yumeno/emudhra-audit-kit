"""No installation or config changes. Output a JSON array for ONE URL."""
import importlib
import json
import ssl
import sys
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


# OpenSSL: unable to get issuer (locally) / self-signed in chain / unable to verify leaf / revoked /
# certificate rejected (28, X509_V_ERR_CERT_REJECTED: some CPython builds return it
# for the base route; CPython's fix gh-160040 rejects the compromised intermediates this way).
# Windows (truststore puts the HRESULT in verify_code): CRYPT_E_REVOKED, CERT_E_UNTRUSTEDROOT,
# CERT_E_CHAINING, TRUST_E_EXPLICIT_DISTRUST. Expiry and name errors are deliberately absent.
REJECT_CODES = {19, 20, 21, 23, 28, 0x80092010, 0x800B0109, 0x800B010A, 0x800B0111}


def classify_exception(error):
    """Inspect structured exceptions, not localized message substrings."""
    pending = [error]
    seen = set()
    codes = []
    for _ in range(50):
        if not pending:
            break
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, ssl.SSLCertVerificationError):
            code = getattr(current, 'verify_code', None)
            if isinstance(code, int) and code < 0:
                code &= 0xFFFFFFFF   # an HRESULT may arrive as a signed 32-bit value
            codes.append(code)
        for name in ('__cause__', '__context__', 'reason'):
            child = getattr(current, name, None)
            if isinstance(child, BaseException):
                pending.append(child)
        pending.extend(child for child in getattr(current, 'args', ())
                       if isinstance(child, BaseException))
    if codes and all(code in REJECT_CODES for code in codes):
        return 'REJECT', 'verify_codes=' + repr(codes)
    return 'UNKNOWN', 'exception=' + type(error).__name__ + '; verify_codes=' + repr(codes)


def urllib_probe(url, cafile=None):
    try:
        # Explicit cafile prevents loading Windows CA/ROOT via load_default_certs.
        ctx = ssl.create_default_context(cafile=cafile)
        opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ctx))
        with opener.open(url, timeout=15) as response:
            return 'ACCEPT', 'http=' + str(response.status)
    except urllib.error.HTTPError as error:
        code = error.code
        # The TLS handshake already succeeded (the server sent an HTTP status), so a failure while
        # closing must not change the verdict. Python 3.9 raises KeyError when the error has no body.
        try:
            error.close()
        except Exception:
            pass
        # Proxy authentication/rejection is not evidence about target TLS.
        if code == 407:
            return 'UNKNOWN', 'proxy authentication required'
        return 'ACCEPT', 'http=' + str(code)
    except Exception as error:
        return classify_exception(error)


def optional_module(name):
    try:
        return importlib.import_module(name), None
    except ModuleNotFoundError as error:
        if error.name == name:
            return None, ('NONE', 'not installed')
        return None, ('UNKNOWN', 'dependency missing')
    except Exception:
        return None, ('UNKNOWN', 'module import failed')


def probe(url):
    result = []
    def add(route, outcome):
        result.append(dict(route=route, verdict=outcome[0], detail=outcome[1]))
    add('stdlib-ssl', urllib_probe(url))
    certifi, failure = optional_module('certifi')
    if failure:
        add('certifi', failure)
    else:
        try:
            add('certifi', urllib_probe(url, certifi.where()))
        except Exception as error:
            add('certifi', classify_exception(error))
    requests, failure = optional_module('requests')
    if failure:
        add('requests', failure)
    else:
        try:
            with requests.get(url, timeout=15, allow_redirects=False) as response:
                add('requests', ('UNKNOWN', 'proxy authentication required') if response.status_code == 407
                    else ('ACCEPT', 'http=' + str(response.status_code)))
        except Exception as error:
            add('requests', classify_exception(error))
    return result


if __name__ == '__main__':
    if len(sys.argv) != 2 or not sys.argv[1].startswith('https://'):
        raise SystemExit('One HTTPS URL required.')
    print(json.dumps(probe(sys.argv[1]), ensure_ascii=True))
