# Shibboleth IdP JWT authentication module

[![Build Status](https://travis-ci.org/KULeuven-CCIS/idp-authn-jwt.svg?branch=master)](https://travis-ci.org/KULeuven-CCIS/idp-authn-jwt)

This authentication module can be used to authenticate the user based on a JWT-token which is send to the IdP via a
common domain cookie. We use this to enable Single Sign-On between our account management system and Shibboleth IdP3
system who share a common domain.

This project is hosted and used by the [KU Leuven University](https://www.kuleuven.be).

The JWT-token must have at least the following claims:

```json
{
    "sub":"userid",
    "iss":"https:\/\/account.example.com",
    "iat":1488538159
}
```

We assume that the JWT is signed (using the private key of the account management system) and encrypted (using the 
public key of the Shibboleth IdP system).

We used EC-keys to do the signing & encryption. The code has some dependencies on those keys, so it is not interchangeable 
with RSA-keys without code modifications.

In any event the cookie that is configured to contain the JWT will be removed (even if the content cannot be validated).

## Build and install

```bash
git clone https://github.com/KULeuven-CCIS/idp-authn-jwt.git
cd idp-authn-jwt/
mvn package
```

Copy jar & dependencies (of course versions can vary in the future). Be sure not to duplicate/conflict jars with ```$IDP_HOME/webapp/WEB-INF/lib/```

```bash
cp target/idp-authn-jwt*jar $IDP_HOME/edit-webapp/WEB-INF/lib/
cp ~/.m2/repository/com/nimbusds/nimbus-jose-jwt/4.34.2/nimbus-jose-jwt-4.34.2.jar $IDP_HOME/edit-webapp/WEB-INF/lib/
cp ~/.m2/repository/net/minidev/json-smart/1.3.1/json-smart-1.3.1.jar $IDP_HOME/edit-webapp/WEB-INF/lib/
cp ~/.m2/repository/com/github/stephenc/jcip/jcip-annotations/1.0-1/jcip-annotations-1.0-1.jar $IDP_HOME/edit-webapp/WEB-INF/lib/
cp ~/.m2/repository/org/bouncycastle/bcpkix-jdk15on/1.54/bcpkix-jdk15on-1.54.jar $IDP_HOME/edit-webapp/WEB-INF/lib/

cd $IDP_HOME
./bin/build.sh
```

Copy the configuration files:

```bash
cp target/classes/conf/authn/jwt-authn-* $IDP_HOME/conf/authn/
cp target/classes/conf/jwt.properties $IDP_HOME/conf/
mkdir $IDP_HOME/flows/authn/jwt
cp target/classes/flows/authn/jwt/jwt-authn-flow.xml $IDP_HOME/flows/authn/jwt/
```

## Generate EC-keys

Generate EC-keypair and extract public key. Provide this public key to the system who is responsible for creating the
JWT. 

```bash
openssl ecparam -genkey -name secp521r1 -noout -out $IDP_HOME/credentials/ec-keypair.pem
openssl ec -in iam-ec512-key-pair.pem -pubout -out $IDP_HOME/credentials/ec-pubkey.pem
```

You will need the public key from the system that will sign the JWT, save this at 
```$IDP_HOME/credentials/account.example.com-pubkey.pem```


## Configuration

Edit the following properties to $IDP_HOME/conf/jwt.properties (usually /opt/shibboleth-idp)

```
idp.authn.jwt.issuer=https://account.example.com
idp.authn.jwt.issuer_pubkey=%{idp.home}/credentials/account.example.com-pubkey.pem
idp.authn.jwt.expiration=PT3M
idp.authn.jwt.privatekey=%{idp.home}/credentials/ec-keypair.pem
idp.authn.jwt.jws.algorithms=ES512,ES384,ES256
idp.authn.jwt.jwe.algorithms=ECDH-ES,ECDH-ES+A128KW,ECDH-ES+A192KW,ECDH-ES+A256KW
idp.authn.jwt.jwe.enc_methods=A256GCM
idp.authn.jwt.cookie_name=jwtidp
idp.authn.jwt.cookie_domain=.example.com
```

Edit $IDP_HOME/conf/idp.properties and add reference to jwt.properties file

```
idp.additionalProperties = /conf/ldap.properties, /conf/saml-nameid.properties, /conf/services.properties, /conf/jwt.properties
```

Configure the authn/MFA flow to look for a JWT, if success, proceed, otherwise fallback to Password.
 
Edit $IDP_HOME/conf/idp.properties 

```
idp.authn.flows=MFA
```

Add the following bean to ```$IDP_HOME/conf/authn/general-authn.xml```

In list "shibboleth.AvailableAuthenticationFlows":

```xml
<bean id="authn/jwt" parent="shibboleth.AuthenticationFlow"
        p:passiveAuthenticationSupported="false"
        p:forcedAuthenticationSupported="false">
    <property name="supportedPrincipals">
        <util:list>
            <bean parent="shibboleth.SAML2AuthnContextClassRef" c:classRef="https://account.example.com/jwt" />
        </util:list>
    </property>
</bean>

<bean id="authn/MFA" parent="shibboleth.AuthenticationFlow"
        p:passiveAuthenticationSupported="true"
        p:forcedAuthenticationSupported="true">
    <property name="supportedPrincipals">
        <list>
            <bean parent="shibboleth.SAML2AuthnContextClassRef" c:classRef="urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" />
            <bean parent="shibboleth.SAML2AuthnContextClassRef" c:classRef="https://account.example.com/jwt" />
        </list>
    </property>
</bean>
```

Example configuration for authn/MFA:

```xml
    <util:map id="shibboleth.authn.MFA.TransitionMap">
        <entry key="">
            <bean parent="shibboleth.authn.MFA.Transition" p:nextFlow="authn/jwt" />
        </entry>

        <entry key="authn/jwt">
            <bean parent="shibboleth.authn.MFA.Transition">
                <property name="nextFlowStrategyMap">
                    <map>
                        <entry key="ReselectFlow" value="authn/Password" />
                    </map>
                </property>
            </bean>
        </entry>
        <!-- An implicit final rule will return whatever the final flow returns. -->
    </util:map>
```
