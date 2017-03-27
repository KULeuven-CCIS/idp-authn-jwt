package be.kuleuven.ccis.shibboleth.idp.authn.impl;

import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.servlet.http.Cookie;

/**
 * Created by philip on 02.03.17.
 */
public class ResetJWTCookie extends AbstractProfileAction {


    /**
     * Class logger.
     */
    @Nonnull
    @NotEmpty
    private final Logger log = LoggerFactory.getLogger(ResetJWTCookie.class);

    private final String cookieName;
    private final String cookieDomain;

    public ResetJWTCookie(String cookieName, String cookieDomain) {
        this.cookieName = cookieName;
        this.cookieDomain = cookieDomain;
    }

    @Override
    protected void doExecute(@Nonnull ProfileRequestContext profileRequestContext) {
        log.debug("Removing JWT cookie {}", cookieName);
        //remove jwt cookie
        Cookie jwtCookie = new Cookie(cookieName, "");
        jwtCookie.setMaxAge(0);
        jwtCookie.setPath("/");
        jwtCookie.setDomain(cookieDomain);
        jwtCookie.setSecure(true);
        jwtCookie.setHttpOnly(true);
        this.getHttpServletResponse().addCookie(jwtCookie);
    }
}
