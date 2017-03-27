package be.kuleuven.ccis.shibboleth.idp.authn.impl;

import be.kuleuven.ccis.shibboleth.idp.authn.context.JWTContext;
import net.shibboleth.idp.authn.AbstractExtractionAction;
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

/**
 * Created by philip on 28.02.2017
 */
public class JWTExtractUsername extends AbstractExtractionAction {
    /**
     * Class logger.
     */
    @Nonnull
    @NotEmpty
    private final Logger log = LoggerFactory.getLogger(JWTExtractUsername.class);

    private JWTContext jwtCtx;


    private final JWTProcessor jwtProcessor;

    public JWTExtractUsername(JWTProcessor jwtProcessor) {
        this.jwtProcessor = jwtProcessor;
    }

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


        log.debug("{} attempting to validate JWT {}", getLogPrefix(), jwtCtx.getJwt());

        String jwtSubject = jwtProcessor.validateAndExtractSubjectFromJWT(jwtCtx.getJwt());

        if (jwtSubject == null) {
            log.warn("Could not extract user from Signed & Encrypted JWT, continuing with other authn modules");
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.RESELECT_FLOW);
        } else {
            log.info("Successfuly decrypted, validated and extracted subject from JWT: {}", jwtSubject);
            jwtCtx.setUsername(jwtSubject);
            ActionSupport.buildProceedEvent(profileRequestContext);
        }

    }


}
