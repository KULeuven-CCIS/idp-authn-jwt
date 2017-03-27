package be.kuleuven.ccis.shibboleth.idp.authn.impl;

import be.kuleuven.ccis.shibboleth.idp.authn.context.JWTContext;
import net.shibboleth.idp.authn.AbstractValidationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.security.auth.Subject;
import javax.servlet.http.Cookie;

/**
 * Created by philip on 28.02.2017
 */
public class JWTValidator extends AbstractValidationAction {
    /**
     * Class logger.
     */
    @Nonnull
    @NotEmpty
    private final Logger log = LoggerFactory.getLogger(JWTValidator.class);

    private JWTContext jwtCtx;

    protected boolean doPreExecute(@Nonnull ProfileRequestContext profileRequestContext, @Nonnull AuthenticationContext authenticationContext) {

        jwtCtx = authenticationContext.getSubcontext(JWTContext.class);
        if (jwtCtx == null) {
            this.log.error("{} Could not get JWTContext", this.getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.INVALID_AUTHN_CTX);
            return false;
        }

        return super.doPreExecute(profileRequestContext, authenticationContext);
    }


    /**
     * {@inheritDoc}
     */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
                             @Nonnull final AuthenticationContext authenticationContext) {


        if (jwtCtx.getUsername() == null || jwtCtx.getUsername().equals("")) {
            log.error("Could not extract user JWTContext");
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.AUTHN_EXCEPTION);
        } else {
            log.info("Username {} successfully authenticated by JWT-cookie", jwtCtx.getUsername());
            buildAuthenticationResult(profileRequestContext, authenticationContext);
            ActionSupport.buildProceedEvent(profileRequestContext);
        }
    }

    @Override
    protected Subject populateSubject(Subject subject) {
        log.debug("{} Populate subject {}", getLogPrefix(), jwtCtx.getUsername());
        subject.getPrincipals().add(new UsernamePrincipal(jwtCtx.getUsername()));
        return subject;
    }


}
