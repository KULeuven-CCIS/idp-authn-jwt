package be.kuleuven.ccis.shibboleth.idp.authn.impl;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.time.Duration;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


/**
 * Created by philip on 28.02.17.
 */
public class JWTProcessor {

    /**
     * Class logger.
     */
    @Nonnull
    @NotEmpty
    private final Logger log = LoggerFactory.getLogger(JWTProcessor.class);

    private final ECPrivateKey privateKey;
    private final ECPublicKey publicKey;
    private final List<JWEAlgorithm> jweAlgorithms;
    private final List<JWSAlgorithm> jwsAlgorithms;
    private final List<EncryptionMethod> encryptionMethods;
    private final Duration expiration;
    private final Map<String, ECPublicKey> issuers;

    public JWTProcessor(String privatekey,
                        List<String> jweAlgorithms,
                        List<String> jwsAlgorithms,
                        List<String> jweEncMethods,
                        String jwtExpiration,
                        Map<String,String> trustedIssuers) {

        // Load BouncyCastle as JCA provider
        Security.addProvider(new BouncyCastleProvider());

        KeyPair keyPair = this.getKeyPair(privatekey);
        // Set private + public EC key
        this.privateKey = (ECPrivateKey)keyPair.getPrivate();
        this.publicKey = (ECPublicKey)keyPair.getPublic();

        this.jweAlgorithms = jweAlgorithms.stream().map(e -> JWEAlgorithm.parse(e)).collect(Collectors.toList());
        this.jwsAlgorithms = jwsAlgorithms.stream().map(e -> JWSAlgorithm.parse(e)).collect(Collectors.toList());
        this.encryptionMethods = jweEncMethods.stream().map(e -> EncryptionMethod.parse(e)).collect(Collectors.toList());
        this.expiration = Duration.parse(jwtExpiration);

        this.issuers = trustedIssuers.entrySet().stream()
                        .collect(Collectors.toMap(
                                e -> e.getKey(),
                                e -> (ECPublicKey) this.getPublicKey(e.getValue())
                        ));
    }


    private PublicKey getPublicKey(String file){
        try {
            // Parse the EC key pair
            PEMParser pemParser = new PEMParser(new InputStreamReader(new FileInputStream(file)));
            SubjectPublicKeyInfo pemKeyPair = (SubjectPublicKeyInfo) pemParser.readObject();
            pemParser.close();
            // Convert to Java (JCA) format
            return new JcaPEMKeyConverter().getPublicKey(pemKeyPair);
        } catch (IOException e) {
            log.error("Failed to parse public key: {}", file);
        }
        return null;
    }

    private KeyPair getKeyPair(String file){
        try {
            // Parse the EC key pair
            PEMParser pemParser = new PEMParser(new InputStreamReader(new FileInputStream(file)));
            PEMKeyPair pemKeyPair = (PEMKeyPair)pemParser.readObject();
            // Convert to Java (JCA) format
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            pemParser.close();
            return converter.getKeyPair(pemKeyPair);
        } catch (IOException e) {
            log.error("Failed to parse keypair key: {}", file);
        }
        return null;
    }

    public String validateAndExtractSubjectFromJWT(String jwt) {

        try {
            JWEObject jweObject = JWEObject.parse(jwt);
            if (! jweAlgorithms.contains(jweObject.getHeader().getAlgorithm()) ||
                  ! encryptionMethods.contains(jweObject.getHeader().getEncryptionMethod())) {
                log.warn("JWE was encrypted using a different algorithm ({}) or encryption method ({})",
                        jweObject.getHeader().getAlgorithm(),
                        jweObject.getHeader().getEncryptionMethod());
                return null;
            }

            jweObject.decrypt(new ECDHDecrypter(this.privateKey));

            SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
            if(! jwsAlgorithms.contains(signedJWT.getHeader().getAlgorithm())) {
                log.warn("JWS was signed using a different algorithm ({})", signedJWT.getHeader().getAlgorithm());
                return null;
            }

            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

            if(claimsSet.getIssuer() == null || claimsSet.getSubject() == null || claimsSet.getIssueTime() == null) {
                log.warn("JWT did not contain the required elements: sub, iat, iss: {}", claimsSet.toJSONObject().toJSONString());
            }

            if(! issuers.containsKey(claimsSet.getIssuer())) {
                log.warn("JWS did not came from a trusted issuer: {}", claimsSet.getIssuer());
                return null;
            }

            if(signedJWT.verify(new ECDSAVerifier(issuers.get(claimsSet.getIssuer())))) {
                log.info("Signature of JWT signed by {} is correct", claimsSet.getIssuer());
                ZonedDateTime issueTime = ZonedDateTime.ofInstant(claimsSet.getIssueTime().toInstant(), ZoneId.systemDefault());

                if (issueTime.plus(expiration).isAfter(ZonedDateTime.now())){
                    log.debug("JWT is valid for user {}. JWT was created at: ", claimsSet.getSubject(), issueTime.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));
                    return claimsSet.getSubject();
                } else {
                    log.warn("JWT has expired. Issued at {}. Expiration at {}.",
                            issueTime.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME),
                            issueTime.plus(expiration).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));
                    return null;
                }

            }

        } catch (ParseException e) {
            log.error("Unable to parse JWT: {}", e.getMessage());
        } catch (JOSEException e) {
            log.error("Unable to decrypt or verify signature: {}", e.getMessage());
        }
        return null;

    }
}
