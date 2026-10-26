// TLS probe for a Java runtime's default trust (cacerts or javax.net.ssl.trustStore, and the runtime's own
// distrust/blocked lists). Java 11+ runs it without compiling:  <java> TlsProbe.java https://host/
// Prints one line "VERDICT<TAB>detail" with VERDICT in ACCEPT / REJECT / UNKNOWN; always exits 0.
// REJECT when the runtime names the reason (distrusted / untrusted / revoked) and nothing unrelated (expiry, name,
// key usage) is reported. The generic "unable to find valid certification path" does not say why the path failed
// (expiry, constraints, algorithms, names, missing intermediates are absorbed), so it is REJECT only when no trust
// anchor exists for the presented chain (no certificate the server sent is trusted itself or issued by a trusted
// certificate) and a diagnostic handshake that trusts only the pinned test roots below passes the runtime's full
// validation for the host. Otherwise it stays UNKNOWN. The network path is not covered by the kit's offline tests.
import java.io.ByteArrayInputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Base64;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;

public class TlsProbe {
    static final X509Certificate[][] presented = new X509Certificate[1][];   // chain of the first (real) handshake
    static X509Certificate[] trusted = new X509Certificate[0];

    // Delegates every decision to d; only records the chain the server presented into slot[0].
    static X509ExtendedTrustManager recording(final X509ExtendedTrustManager d, final X509Certificate[][] slot) {
        return new X509ExtendedTrustManager() {
            public void checkServerTrusted(X509Certificate[] c, String a, Socket s) throws CertificateException { slot[0] = c; d.checkServerTrusted(c, a, s); }
            public void checkServerTrusted(X509Certificate[] c, String a, SSLEngine e) throws CertificateException { slot[0] = c; d.checkServerTrusted(c, a, e); }
            public void checkServerTrusted(X509Certificate[] c, String a) throws CertificateException { slot[0] = c; d.checkServerTrusted(c, a); }
            public void checkClientTrusted(X509Certificate[] c, String a, Socket s) throws CertificateException { d.checkClientTrusted(c, a, s); }
            public void checkClientTrusted(X509Certificate[] c, String a, SSLEngine e) throws CertificateException { d.checkClientTrusted(c, a, e); }
            public void checkClientTrusted(X509Certificate[] c, String a) throws CertificateException { d.checkClientTrusted(c, a); }
            public X509Certificate[] getAcceptedIssuers() { return d.getAcceptedIssuers(); }
        };
    }

    // Roots that issue the top of the test hosts' chains: the eMudhra path ends with
    // "emSign Root TLS CA - G3" issued by "emSign ECC Root CA - G3"; the Sectigo cross-signed path ends with
    // "EM DV TLS CA - G3B" issued by "AAA Certificate Services". Pinned as certificates (public data, DER in base64)
    // and used only by the diagnostic handshake in diagnose().
    // AAA Certificate Services, SHA-256 D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4
    // emSign ECC Root CA - G3,  SHA-256 86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B
    static final String[] KNOWN_ROOTS_B64 = {
            "MIIEMjCCAxqgAwIBAgIBATANBgkqhkiG9w0BAQUFADB7MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVz" +
            "dGVyMRAwDgYDVQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UEAwwYQUFBIENlcnRpZmlj" +
            "YXRlIFNlcnZpY2VzMB4XDTA0MDEwMTAwMDAwMFoXDTI4MTIzMTIzNTk1OVowezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdy" +
            "ZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNVBAMM" +
            "GEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL5AnfRu4ep2hxxNRUSO" +
            "vkbIgwadwSr+GB+O5AL686tdUIoWMQuaBtDFcCLNSS1UY8y2bmhGC1Pqy0wkwLxyTurxFa70VJoSCsN6sjNg4tqJVfMiWPPe" +
            "3M/vg4aijJRPn2jymJBGhCfHdr/jzDUsi14HZGWCwEiwqJH5YZ92IFCokcdmtet4YgNW8IoaE+oxox6gmf049vYnMlhvB/Vr" +
            "uPsUK6+3qszWY19zjNoFmag4qMsXeDZRrOme9Hg6jc8P2ULimAyrL58OAd7vn5lJ8S3frHRNG5i1R8XlKdH5kBjHYpy+g8cm" +
            "ez6KJcfA3Z3mNWgQIJ2P2N7Sw4ScDV7oL8kCAwEAAaOBwDCBvTAdBgNVHQ4EFgQUoBEKIz6W8Qfs4q8p74Klf9AwpLQwDgYD" +
            "VR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wewYDVR0fBHQwcjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9jYS5jb20v" +
            "QUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNqA0oDKGMGh0dHA6Ly9jcmwuY29tb2RvLm5ldC9BQUFDZXJ0aWZpY2F0ZVNl" +
            "cnZpY2VzLmNybDANBgkqhkiG9w0BAQUFAAOCAQEACFb8AvCb6P+k+tZ7xkSAzk/ExfYAWMymtrwUSWgEdujm7l3sAg9g1o1Q" +
            "GE8mTgHj5rCl7r+8dFRBv/38ErjHT1r0iWAFf2C3BUrz9vHCv8S5dIa2LX1rzNLzRt0vxuBqw8M0Ayx9lt1awg6nCpnBBYur" +
            "DC/zXDrPbDdVCYfeU0BsWO/8tqtlbgT2G9w84FoVxp7Z8VlIMCFlA2zs6SFz7JsDoeA3raAVGI/6ugLOpyypEBMs1OUIJqsi" +
            "l2D4kF501KKaU73yqWjgom7C12yxow+ev+to51byrvLjKzg6CYG1a4XXvi3tPxq3smPi9WIsgtRqAEFQ8TmDn5XpNpaYbg==",
            "MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQGEwJJTjETMBEGA1UECxMKZW1TaWduIFBL" +
            "STElMCMGA1UEChMcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0g" +
            "RzMwHhcNMTgwMjE4MTgzMDAwWhcNNDMwMjE4MTgzMDAwWjBrMQswCQYDVQQGEwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTEl" +
            "MCMGA1UEChMcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0gRzMw" +
            "djAQBgcqhkjOPQIBBgUrgQQAIgNiAAQjpQy4LRL1KPOxst3iAhKAnjlfSU2fySU0WXTsuwYc58Byr+iuL+FBVIcUqEqy6HyC" +
            "5ltqtdyzdc6LBtCGI79G1Y4PPwT01xySfvalY8L1X44uT6EYGQIrMgqCZH0Wk9GjQjBAMB0GA1UdDgQWBBR8XQKEE9TMipuB" +
            "zhccLikenEhjQjAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNpADBmAjEAvvNhzwIQHWSV" +
            "B7gYboiFBS+DCBeQyh+KTOgNG3qxrdWBCUfvO6wIBHxcmbHtRwfSAjEAnbpV/KlK6O3t5nYBQnvI+GDZjVGLVTv7jHvrZQnD" +
            "+JbNR6iC8hZVdyR+EhCVBCyj",
    };

    static X509Certificate[] knownRoots() throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate[] r = new X509Certificate[KNOWN_ROOTS_B64.length];
        for (int i = 0; i < r.length; i++) {
            r[i] = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(KNOWN_ROOTS_B64[i])));
        }
        return r;
    }

    static final String NO_ANCHOR = "no trust anchor for the presented chain";

    // NO_ANCHOR only when nothing the server sent is, or is issued by, a certificate the runtime trusts.
    static String anchorReason(X509Certificate[] chain, X509Certificate[] anchors) {
        if (chain == null || chain.length == 0) return "no presented chain recorded";
        if (anchors.length == 0) return "trust store empty or not readable";
        for (X509Certificate x : chain) {
            for (X509Certificate a : anchors) {
                if (a.getSubjectX500Principal().equals(x.getIssuerX500Principal()) || a.equals(x)) {
                    return "a trust anchor exists for the presented chain; the path failed for another reason";
                }
            }
        }
        return NO_ANCHOR;
    }

    // One TLS handshake with host-name verification. Returns the protocol, or throws.
    static String handshake(String host, TrustManager tm) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[] { tm }, null);
        try (Socket raw = new Socket()) {
            raw.connect(new InetSocketAddress(host, 443), 15000);
            raw.setSoTimeout(15000);
            try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket(raw, host, 443, true)) {   // sets SNI from host
                SSLParameters p = s.getSSLParameters();
                p.setEndpointIdentificationAlgorithm("HTTPS");
                s.setSSLParameters(p);
                s.startHandshake();
                return s.getSession().getProtocol();
            }
        }
    }

    static String causes(Throwable e) {
        StringBuilder b = new StringBuilder();
        for (Throwable c = e; c != null; c = c.getCause()) b.append(c.getClass().getSimpleName()).append(": ").append(c.getMessage()).append(" | ");
        return b.toString();
    }

    static boolean sameChain(X509Certificate[] a, X509Certificate[] b) {
        if (a == null || b == null || a.length != b.length) return false;
        try {
            for (int i = 0; i < a.length; i++) if (!Arrays.equals(a[i].getEncoded(), b[i].getEncoded())) return false;
        } catch (Exception e) { return false; }
        return true;
    }

    // Diagnostic only (never used for ACCEPT): a second handshake that trusts nothing but the pinned test roots, with the
    // runtime's own full validation (host name, key usage, constraints, algorithms, validity, complete path). Success,
    // with the server presenting byte-for-byte the same chain as in the first handshake, means that chain is a valid
    // TLS server chain for this host up to a pinned root.
    static String diagnose(String host, X509Certificate[] first) {
        try {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            X509Certificate[] roots = knownRoots();
            for (int i = 0; i < roots.length; i++) ks.setCertificateEntry("pinned-root-" + i, roots[i]);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            X509ExtendedTrustManager pinned = null;
            for (TrustManager t : tmf.getTrustManagers()) if (t instanceof X509ExtendedTrustManager) pinned = (X509ExtendedTrustManager) t;
            if (pinned == null) return "diagnostic trust manager unavailable";
            final X509Certificate[][] second = new X509Certificate[1][];
            handshake(host, recording(pinned, second));
            if (!sameChain(first, second[0])) return "diagnostic handshake got a different chain (load balancer or certificate change)";
            return "ok";
        } catch (Exception e) {
            return "diagnostic validation with the pinned test roots failed: " + causes(e).replace(host, "<host>");
        }
    }

    public static void main(String[] args) {
        String host;
        try {
            host = new URI(args[0]).getHost();
            if (host == null) throw new IllegalArgumentException("no host");
        } catch (Exception e) { System.out.println("UNKNOWN\tbad url"); return; }
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null);   // the runtime's default trust, as an application would get it
            X509ExtendedTrustManager base = null;
            for (TrustManager t : tmf.getTrustManagers()) {
                if (t instanceof X509ExtendedTrustManager) base = (X509ExtendedTrustManager) t;
            }
            if (base == null) { System.out.println("UNKNOWN\tno X509ExtendedTrustManager"); return; }
            trusted = base.getAcceptedIssuers();
            System.out.println("ACCEPT\thandshake ok " + handshake(host, recording(base, presented)));
        } catch (Exception e) {
            String text = causes(e).replace(host, "<host>");   // the host name must not decide the verdict
            String lower = text.toLowerCase();
            String verdict = "UNKNOWN";
            String note = "";
            if (lower.matches("(?s).*(expired|not yet valid|no subject alternative|no name matching|key usage).*")) {
                note = "not related";
            } else if (lower.matches("(?s).*(distrusted|untrusted|revoked).*")) {
                verdict = "REJECT"; note = "named reason";
            } else if (lower.contains("unable to find valid certification path")) {
                note = anchorReason(presented[0], trusted);
                if (note.equals(NO_ANCHOR)) {
                    String diag = diagnose(host, presented[0]);
                    if (diag.equals("ok")) { verdict = "REJECT"; note = NO_ANCHOR + "; valid TLS chain for the host under the pinned test roots"; }
                    else note = NO_ANCHOR + "; " + diag;
                }
            }
            System.out.println(verdict + "\t" + note + "; " + text.replace('\t', ' ').replace('\n', ' ').replace('\r', ' '));
        }
    }
}
