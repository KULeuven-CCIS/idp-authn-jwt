package be.kuleuven.ccis.shibboleth.idp.authn.context;

import org.opensaml.messaging.context.BaseContext;
/**
 * Created by philip on 17.03.16.
 */
public class JWTContext extends BaseContext {
    private String jwt;
    private String username;

    public String getJwt() {
        return jwt;
    }

    public void setJwt(String jwt) {
        this.jwt = jwt;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

}
