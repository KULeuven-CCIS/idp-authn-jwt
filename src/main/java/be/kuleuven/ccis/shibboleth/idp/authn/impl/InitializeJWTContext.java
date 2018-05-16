package be.kuleuven.ccis.shibboleth.idp.authn.impl;

import be.kuleuven.ccis.shibboleth.idp.authn.context.JWTContext;
import net.shibboleth.idp.authn.AbstractExtractionAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.servlet.http.Cookie;
import java.util.Arrays;

/**
 * Created by philip on 28.02.17.
 */
public class InitializeJWTContext extends AbstractExtractionAction {

    /**
     * Class logger.
     */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(InitializeJWTContext.class);

    private JWTContext jwtCtx;
    private final String cookieName;

    public InitializeJWTContext(String cookieName) {
        this.cookieName = cookieName;
    }

    /**
     * Performs this authentication action's pre-execute step. Default implementation just returns true.
     *
     * @param profileRequestContext the current IdP profile request context
     * @param authenticationContext the current authentication context
     * @return true iff execution should continue
     */
    @Override
    protected boolean doPreExecute(ProfileRequestContext profileRequestContext, AuthenticationContext authenticationContext) {

        //get JWTContext and create if it doesn't exist already
        jwtCtx = authenticationContext.getSubcontext(JWTContext.class, true);

        if (jwtCtx == null) {
            log.error("{} Could not create JWTContext", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
            return false;
        }

        return super.doPreExecute(profileRequestContext, authenticationContext);
    }

    /**
     * Performs this authentication action. Default implementation throws an exception.
     *
     * @param profileRequestContext the current IdP profile request context
     * @param authenticationContext the current authentication context
     */
    @Override
    protected void doExecute(ProfileRequestContext profileRequestContext, AuthenticationContext authenticationContext) {

        Cookie jwtCookie = null;
        if (this.getHttpServletRequest().getCookies() != null) {
          jwtCookie = Arrays.stream(this.getHttpServletRequest().getCookies())
                .filter(x -> cookieName.equals(x.getName()))
                .findAny()
                .orElse(null);
        }

        if (jwtCookie == null) {
                log.debug("{} No JWT cookie found with name: {}", getLogPrefix(), cookieName);
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
                return;
        }
        jwtCtx.setJwt(jwtCookie.getValue());

    }

}
