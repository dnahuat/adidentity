package org.baco.adidentity;

import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.build.JwtClaimsBuilder;
import org.baco.adidentity.ad.ActiveDirectory;
import org.baco.adidentity.ad.ActiveDirectoryConfiguration;
import org.baco.adidentity.ad.User;
import org.baco.adidentity.jwt.JWTConfig;
import org.baco.adidentity.jwt.JWTUtils;
import org.eclipse.microprofile.config.ConfigProvider;
import org.eclipse.microprofile.jwt.JsonWebToken;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.*;

@Path("/auth")
@RequestScoped
public class AuthEndpoint {

    private static String USER_NOT_FOUND = "User not found in Active Directory.";

    @Inject
    ActiveDirectory activeDirectory;

    @Inject
    ActiveDirectoryConfiguration activeDirectoryConfiguration;

    @Inject
    JWTConfig jwtConfig;

    @Inject
    JsonWebToken jwt;

    @POST
    @Path("/login")
    @PermitAll
    @Produces(MediaType.TEXT_PLAIN)
    public Response login(@HeaderParam("username") String username, @HeaderParam("password") String password) {
        if(username != null && !username.trim().isEmpty() && password != null && !password.trim().isEmpty()) {
            try {
                // Try to connect with provided credentials
                LdapContext adContext = activeDirectory.getConnection(username.trim(), password.trim());
                User user = activeDirectory.getUser(adContext, username.trim());
                adContext.close();
                try {
                    String signedJWT = getSignedJWT(username.trim(), user.getUserPrincipal(), user.getName(), user.getDepartment(), user.getTitle());
                    return Response.ok(signedJWT).build();
                } catch (Exception ex) {
                    return Response.serverError().build();
                }
            } catch (NamingException ex) {
                return Response.status(Response.Status.NOT_FOUND).build();
            }
        } else {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
    }

    @GET
    @Path("/user-info/{adUser}")
    @RolesAllowed({"Users"})
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUserInfo(@PathParam("adUser") String adUser) {
        if(adUser != null && !adUser.trim().isEmpty()) {
            try {
                User user = activeDirectory.getUser(adUser);
                return Response.ok(user, MediaType.APPLICATION_JSON).build();
            } catch (NamingException ex) {
                return Response.status(Response.Status.NOT_FOUND).build();
            }
        } else {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

    }

    @POST
    @Path("/verify")
    @RolesAllowed({"Users"})
    @Produces(MediaType.APPLICATION_JSON)
    public Response verifyToken() {
        Set<String> claimNames = jwt.getClaimNames();
        Map<String, Object> claimMap = new HashMap<>();
        claimNames.stream().forEach(c -> claimMap.put(c, jwt.getClaim(c)));
        claimMap.remove("raw_token");
        return Response.ok(claimMap).build();
    }

    @POST
    @Path("/refresh")
    @RolesAllowed({"Users"})
    @Produces(MediaType.TEXT_PLAIN)
    public Response refresh() {
        Long expirationTime = jwt.getExpirationTime();
        /**
         * Verify expiration
         */
        Calendar now = Calendar.getInstance();
        Long curTime = now.getTimeInMillis()/1000;
        Long diff = expirationTime - curTime;

        if(diff < 0 || diff >= 600) {
            return Response.status(Response.Status.FORBIDDEN).build();
        }
        String username = jwt.getClaim("username");
        String userPrincipal = jwt.getClaim("userPrincipal");
        String name = jwt.getClaim("name");
        String department = jwt.getClaim("department");
        String title = jwt.getClaim("title");
        try {
            String signedJWT = getSignedJWT(username, userPrincipal, name, department, title);
            return Response.ok(signedJWT).build();
        } catch (Exception ex) {
            return Response.serverError().build();
        }
    }

    /**
     * Gets a Signed JWT String token with AD common parameters as claims
     * @param username
     * @param userPrincipal
     * @param name
     * @param department
     * @param title
     * @return
     * @throws Exception
     */
    private String getSignedJWT(String username, String userPrincipal, String name, String department, String title) throws Exception {
        Optional<String> issuerConfig = ConfigProvider.getConfig().getOptionalValue(JWTConfig.ISSUER_CONFIG, String.class);
        String issuer = issuerConfig.orElse("baco.adidentity");

        Calendar expiry = Calendar.getInstance();
        expiry.add(Calendar.HOUR, 24);
        // Generate JWT Token
        JwtClaimsBuilder claimBuilder = Jwt.claims();
        claimBuilder.claim("username", username)
                .claim("userPrincipal", userPrincipal)
                .claim("name", name)
                .claim("department", department)
                .claim("title", title)
                .groups("Users") // Add bearer Group
                .issuer(issuer)
                .expiresAt(expiry.getTimeInMillis()/1000);
        // Sign JWT Token
        return claimBuilder.jws().signatureKeyId(jwtConfig.getSignatureId()).sign(JWTUtils.getPrivateKey());
    }

}
