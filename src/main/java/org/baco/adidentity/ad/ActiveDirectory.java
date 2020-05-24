package org.baco.adidentity.ad;

import org.eclipse.microprofile.config.ConfigProvider;
import static javax.naming.directory.SearchControls.SUBTREE_SCOPE;
import java.io.IOException;
import java.security.KeyManagementException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.inject.Singleton;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.*;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Bean that provides methods for accesing an AD server
 */
@Singleton
public class ActiveDirectory {

    private static final Logger LOG = Logger.getLogger(ActiveDirectory.class.getName());


    /**
     * AD attributtes
     */
    private static String[] userAttributes = {
            "distinguishedName", "cn", "name", "uid", "title", "company", "employeeNumber",
            "sn", "givenname", "memberOf", "samaccountname", "department", "telephoneNumber",
            "userPrincipalName", "useraccountcontrol", "whenCreated", "whenChanged"
    };

    private static final SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");

    /**
     * Used to authenticate an user given a username/password and domain name.
     * Provides an option to identify a specific a Active Directory server.
     *
     * @param username username
     * @param password password
     * @return
     * @throws NamingException
     */
    public LdapContext getConnection(String username,
                                     String password) throws NamingException {
        Optional<String> domainConfig = ConfigProvider.getConfig().getOptionalValue(ActiveDirectoryConfiguration.DOMAIN_CONFIG, String.class);
        Optional<String> hostConfig = ConfigProvider.getConfig().getOptionalValue(ActiveDirectoryConfiguration.HOST_CONFIG, String.class);
        Optional<String> portConfig = ConfigProvider.getConfig().getOptionalValue(ActiveDirectoryConfiguration.PORT_CONFIG, String.class);


        String domainName = domainConfig.orElse(ActiveDirectoryConfiguration.DOMAIN_DEFAULT);
        String serverName = hostConfig.orElse(ActiveDirectoryConfiguration.HOST_DEFAULT);
        String port = portConfig.orElse(ActiveDirectoryConfiguration.PORT_DEFAULT);

        if (domainName == null) {
            try {
                String fqdn = java.net.InetAddress.getLocalHost().getCanonicalHostName();
                if (fqdn.split("\\.").length > 1) {
                    domainName = fqdn.substring(fqdn.indexOf(".") + 1);
                }
            } catch (java.net.UnknownHostException e) {
            }
        }

        if (password != null) {
            password = password.trim();
            if (password.length() == 0) {
                password = null;
            }
        }
        //bind by using the specified username/password
        Hashtable props = new Hashtable();
        String principalName = username + "@" + domainName;
        props.put(Context.SECURITY_PRINCIPAL, principalName);
        props.put("com.sun.jndi.ldap.read.timeout", "10000");
        if (password != null) {
            props.put(Context.SECURITY_CREDENTIALS, password);
        }

        String ldapURL =
                "ldap://" + ((serverName == null) ? domainName : serverName) + ":" + port + '/';
        props.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        props.put(Context.PROVIDER_URL, ldapURL);
        try {
            return new InitialLdapContext(props, null);
        } catch (javax.naming.CommunicationException e) {

            Logger.getLogger(ActiveDirectory.class.getName()).
                    log(Level.SEVERE,
                            "Failed to connect to " + domainName + ((serverName == null) ? "" : " through " + serverName), e);

            throw new NamingException("Failed to connect to " + domainName + ((serverName == null) ? "" : " through " + serverName));
        } catch (NamingException e) {
            Logger.getLogger(ActiveDirectory.class.getName()).
                    log(Level.SEVERE,
                            "Failed to authenticate " + username + "@" + domainName + ((serverName == null) ? "" : " through " + serverName), e);
            throw new NamingException("Failed to authenticate " + username + "@" + domainName + ((serverName == null) ? "" : " through " + serverName));
        }
    }

    public User getUser(LdapContext ldapContext, String username) throws NamingException {

        Optional<String> userConfig = ConfigProvider.getConfig().getOptionalValue(ActiveDirectoryConfiguration.USERNAME_CONFIG, String.class);
        Optional<String> passConfig = ConfigProvider.getConfig().getOptionalValue(ActiveDirectoryConfiguration.PASSWORD_CONFIG, String.class);

        String queryUsername = userConfig.orElse(ActiveDirectoryConfiguration.USERNAME_DEFAULT);
        String queryPassword = passConfig.orElse(ActiveDirectoryConfiguration.PASSWORD_DEFAULT);

        /**
         * If a context is not provided then generate from master credentials
         */
        LdapContext context = ldapContext;
        if(context == null) {
            context = getConnection(queryUsername, queryPassword);
        }

        String domainName = null;
        if (username.contains("@")) {
            username = username.substring(0, username.indexOf("@"));
            domainName = username.substring(username.indexOf("@") + 1);
        } else if (username.contains("\\")) {
            username = username.substring(0, username.indexOf("\\"));
            domainName = username.substring(username.indexOf("\\") + 1);
        } else {
            String authenticatedUser = (String) context.getEnvironment().get(Context.SECURITY_PRINCIPAL);
            if (authenticatedUser.contains("@")) {
                domainName = authenticatedUser.substring(authenticatedUser.indexOf("@") + 1);
            }
        }

        if (domainName != null) {
            String principalName = username + "@" + domainName;
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SUBTREE_SCOPE);
            controls.setReturningAttributes(userAttributes);
            NamingEnumeration<SearchResult> answer = context.search(toDC(domainName), "(&(objectCategory=Person)(sAMAccountName=" + username + "))", controls);
            if (answer.hasMore()) {
                User user;
                while (answer.hasMore()) {
                    Attributes attr = ((SearchResult) answer.next()).getAttributes();
                    String userName = (String) (attr.get("samaccountname") != null ? attr.get("samaccountname").get() : "");
                    String userPrincipal = (String) (attr.get("userPrincipalName") != null ? attr.get("userPrincipalName").get() : "");
                    String distinguishedName = (String) (attr.get("distinguishedName") != null ? attr.get("distinguishedName").get() : "");
                    String commonName = (String) (attr.get("cn") != null ? attr.get("cn").get() : "");
                    String userAccountControl = (String) (attr.get("useraccountcontrol") != null ? attr.get("useraccountcontrol").get() : "");
                    String whenCreated = (String) (attr.get("whenCreated") != null ? attr.get("whenCreated").get() : "");
                    whenCreated = whenCreated.substring(0, whenCreated.indexOf("."));
                    String memberOf = (String) (attr.get("memberOf") != null ? attr.get("memberOf").get() : "");
                    String title = (String) (attr.get("title") != null ? attr.get("title").get() : "");
                    String department = (String) (attr.get("department") != null ? attr.get("department").get() : "");
                    String company = (String) (attr.get("company") != null ? attr.get("company").get() : "");
                    String employeeNumber = (String) (attr.get("employeeNumber") != null ? attr.get("employeeNumber").get() : "");
                    String telephoneNumber = (String) (attr.get("telephoneNumber") != null ? attr.get("telephoneNumber").get() : "");
                    user = new User();
                    user.setName(commonName);
                    user.setUsername(userName);
                    user.setUserPrincipal(userPrincipal);
                    user.setDistinguishedName(distinguishedName);
                    user.setSourceType("AD");
                    if (userAccountControl.equals("514") || userAccountControl.equals("66050")) {
                        user.setEnabled(false);
                    } else {
                        user.setEnabled(true);
                    }
                    try {
                        Date createdAt = sdf.parse(whenCreated);
                        user.setCreatedAt(createdAt);
                    } catch (ParseException ex) {
                        LOG.log(Level.FINE, "AD Cannot parse date format {0}.", whenCreated);
                    }
                    user.setMemberOf(memberOf);
                    user.setTitle(title);
                    user.setDepartment(department);
                    user.setCompany(company);
                    user.setEmployeeNumber(employeeNumber);
                    user.setTelephoneNumber(telephoneNumber);
                    return user;
                }
            }
        }
        return null;
    }


    /**
     * Gets user info using configured query credentials
     *
     * @param username The username to query
     * @return User general information
     * @throws NamingException
     */
    public User getUser(String username) throws NamingException {
        return getUser(null, username);
    }

    /**
     * Gets all user in the AD server. Results could be truncated if the server has a query result limit.
     * @return An array of users
     * @throws NamingException
     */
    public List<User> getUsers() throws NamingException {
        Optional<String> userConfig = ConfigProvider.getConfig().getOptionalValue(ActiveDirectoryConfiguration.USERNAME_CONFIG, String.class);
        Optional<String> passConfig = ConfigProvider.getConfig().getOptionalValue(ActiveDirectoryConfiguration.PASSWORD_CONFIG, String.class);

        String queryUsername = userConfig.orElse(ActiveDirectoryConfiguration.USERNAME_DEFAULT);
        String queryPassword = passConfig.orElse(ActiveDirectoryConfiguration.PASSWORD_DEFAULT);

        LdapContext context = getConnection(queryUsername, queryPassword);
        List<User> users = new ArrayList<>();
        String authenticatedUser = (String) context.getEnvironment().get(Context.SECURITY_PRINCIPAL);
        if (authenticatedUser.contains("@")) {
            String domainName = authenticatedUser.substring(authenticatedUser.indexOf("@") + 1);
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SUBTREE_SCOPE);
            controls.setReturningAttributes(userAttributes);
            NamingEnumeration answer = context.search(toDC(domainName), "(objectCategory=Person)", controls);
            User user;
            while (answer.hasMore()) {
                Attributes attr = ((SearchResult) answer.next()).getAttributes();
                String userName = (String) (attr.get("samaccountname") != null ? attr.get("samaccountname").get() : "");
                String userPrincipal = (String) (attr.get("userPrincipalName") != null ? attr.get("userPrincipalName").get() : "");
                String distinguishedName = (String) (attr.get("distinguishedName") != null ? attr.get("distinguishedName").get() : "");
                String commonName = (String) (attr.get("cn") != null ? attr.get("cn").get() : "");
                String userAccountControl = (String) (attr.get("useraccountcontrol") != null ? attr.get("useraccountcontrol").get() : "");
                String whenCreated = (String) (attr.get("whenCreated") != null ? attr.get("whenCreated").get() : "");
                whenCreated = whenCreated.substring(0, whenCreated.indexOf("."));
                String memberOf = (String) (attr.get("memberOf") != null ? attr.get("memberOf").get() : "");
                String title = (String) (attr.get("title") != null ? attr.get("title").get() : "");
                String department = (String) (attr.get("department") != null ? attr.get("department").get() : "");
                String company = (String) (attr.get("company") != null ? attr.get("company").get() : "");
                String employeeNumber = (String) (attr.get("employeeNumber") != null ? attr.get("employeeNumber").get() : "");
                String telephoneNumber = (String) (attr.get("telephoneNumber") != null ? attr.get("telephoneNumber").get() : "");
                user = new User();
                user.setName(commonName);
                user.setUsername(userName);
                user.setUserPrincipal(userPrincipal);
                user.setDistinguishedName(distinguishedName);
                user.setSourceType("AD");
                if (userAccountControl.equals("514") || userAccountControl.equals("66050")) {
                    user.setEnabled(false);
                } else {
                    user.setEnabled(true);
                }
                try {
                    Date createdAt = sdf.parse(whenCreated);
                    user.setCreatedAt(createdAt);
                } catch (ParseException ex) {
                    LOG.log(Level.FINE, "AD Cannot parse date format {0}.", whenCreated);
                }
                user.setMemberOf(memberOf);
                user.setTitle(title);
                user.setDepartment(department);
                user.setCompany(company);
                user.setEmployeeNumber(employeeNumber);
                user.setTelephoneNumber(telephoneNumber);
                users.add(user);
            }
        }
        return users;
    }


    /**
     * Returns all the users paginated providing a delta
     * @param pageSize result page size
     * @param lastChanged delta
     * @return
     * @throws NamingException
     * @throws IOException
     */
    public List<User> getUsers(final Integer pageSize, final Long lastChanged)
            throws NamingException, IOException {
        Optional<String> userConfig = ConfigProvider.getConfig().getOptionalValue(ActiveDirectoryConfiguration.USERNAME_CONFIG, String.class);
        Optional<String> passConfig = ConfigProvider.getConfig().getOptionalValue(ActiveDirectoryConfiguration.PASSWORD_CONFIG, String.class);

        String queryUsername = userConfig.orElse(ActiveDirectoryConfiguration.USERNAME_DEFAULT);
        String queryPassword = passConfig.orElse(ActiveDirectoryConfiguration.PASSWORD_DEFAULT);

        LdapContext context = getConnection(queryUsername, queryPassword);
        List<User> users = new ArrayList<>();

        String authenticatedUser = (String) context.getEnvironment().
                get(Context.SECURITY_PRINCIPAL);
        if (authenticatedUser.contains("@")) {
            String domainName = authenticatedUser.substring(
                    authenticatedUser.indexOf("@") + 1);
            // Controles de consulta paginada
            byte[] cookie = null;
            int total;
            context.setRequestControls(new Control[]{
                    new PagedResultsControl(pageSize, Control.CRITICAL)
            });
            // Controles de busqueda
            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SUBTREE_SCOPE);
            searchControls.setReturningAttributes(userAttributes);
            do {
                LOG.log(Level.FINE, "AD Requesting users");
                String deltaChange = String.format("%014d", lastChanged + 1);
                if (deltaChange.endsWith("60")) { // Segundo 60 no existe se revierte a 59
                    deltaChange = String.format("%014d", lastChanged);
                }
                if (lastChanged == 0) {
                    deltaChange = "20010928060000";
                }
                NamingEnumeration answer = context.search(toDC(domainName),
                        "(&(objectCategory=Person)(whenChanged>=" + deltaChange + ".0Z))", searchControls);
                User user;
                while (answer != null && answer.hasMore()) {
                    Attributes attr = ((SearchResult) answer.next()).getAttributes();
                    String userName = (String) (attr.get("samaccountname") != null ? attr.get("samaccountname").get() : "");
                    String userPrincipal = (String) (attr.get("userPrincipalName") != null ? attr.get("userPrincipalName").get() : "");
                    String distinguishedName = (String) (attr.get("distinguishedName") != null ? attr.get("distinguishedName").get() : "");
                    String commonName = (String) (attr.get("cn") != null ? attr.get("cn").get() : "");
                    String userAccountControl = (String) (attr.get("useraccountcontrol") != null ? attr.get("useraccountcontrol").get() : "");
                    String whenCreated = (String) (attr.get("whenCreated") != null ? attr.get("whenCreated").get() : "");
                    whenCreated = whenCreated.substring(0, whenCreated.indexOf("."));
                    String memberOf = (String) (attr.get("memberOf") != null ? attr.get("memberOf").get() : "");
                    String title = (String) (attr.get("title") != null ? attr.get("title").get() : "");
                    String department = (String) (attr.get("department") != null ? attr.get("department").get() : "");
                    String company = (String) (attr.get("company") != null ? attr.get("company").get() : "");
                    String employeeNumber = (String) (attr.get("employeeNumber") != null ? attr.get("employeeNumber").get() : "");
                    String telephoneNumber = (String) (attr.get("telephoneNumber") != null ? attr.get("telephoneNumber").get() : "");
                    String whenChanged = (String) attr.get("whenChanged").get();
                    whenChanged = whenChanged.substring(0, whenChanged.indexOf("."));
                    user = new User();
                    user.setName(commonName);
                    user.setUsername(userName);
                    user.setUserPrincipal(userPrincipal);
                    user.setDistinguishedName(distinguishedName);
                    user.setSourceType("AD");
                    if (userAccountControl.equals("514") || userAccountControl.equals("66050")) {
                        user.setEnabled(false);
                    } else {
                        user.setEnabled(true);
                    }
                    try {
                        /**
                         * Assign modification to creation date
                         */

                        Date createdAt = sdf.parse((whenChanged == null || whenChanged.length() == 0) ? whenCreated : whenChanged);
                        user.setCreatedAt(createdAt);
                    } catch (ParseException ex) {
                        LOG.log(Level.FINE, "AD Cannot parse date format {0}.", whenCreated);
                    }
                    user.setMemberOf(memberOf);
                    user.setTitle(title);
                    user.setDepartment(department);
                    user.setCompany(company);
                    user.setEmployeeNumber(employeeNumber);
                    user.setTelephoneNumber(telephoneNumber);
                    users.add(user);
                }
                Control[] controls = context.getResponseControls();
                if (controls != null) {
                    for (int i = 0; i < controls.length; i++) {
                        if (controls[i] instanceof PagedResultsResponseControl) {
                            PagedResultsResponseControl prrc =
                                    (PagedResultsResponseControl) controls[i];
                            total = prrc.getResultSize();
                            cookie = prrc.getCookie();
                            LOG.log(Level.FINE, "AD Request executed: Got {0} users.", String.valueOf(total));
                        }
                    }
                }
                context.setRequestControls(new Control[]{
                        new PagedResultsControl(pageSize, cookie, Control.CRITICAL)});
            } while (cookie != null);
        }
        return users;
    }

    /**
     * Gets a dc formatted query using the provided comain
     * @param domainName
     * @return
     */
    private String toDC(String domainName) {
        Optional<String> orgunitConfig = ConfigProvider.getConfig().getOptionalValue(ActiveDirectoryConfiguration.ORGUNIT_CONFIG, String.class);
        String orgUnit = orgunitConfig.orElse(ActiveDirectoryConfiguration.ORGUNIT_DEFAULT);

        StringBuilder buf = new StringBuilder();
        buf.append("OU=");
        buf.append(orgUnit); // ou = usuarios
        for (String token : domainName.split("\\.")) {
            if (token.length() == 0) {
                continue;   // defensive check
            }
            if (buf.length() > 0) {
                buf.append(",");
            }
            buf.append("DC=").append(token);
        }
        return buf.toString();
    }

    /**
     * Used to change the user password. Throws an IOException if the Domain
     * Controller is not LDAPS enabled.
     * If true, bypasses all certificate and host name
     * validation. If false, ensure that the LDAPS certificate has been imported
     * into a trust store and sourced before calling this method. Example:
     * String keystore = "/usr/java/jdk1.5.0_01/jre/lib/security/cacerts";
     * System.setProperty("javax.net.ssl.trustStore",keystore);
     *
     * @param user
     * @param oldPass
     * @param newPass
     * @param trustAllCerts
     * @throws java.io.IOException
     * @throws javax.naming.NamingException
     */
    public void changePassword(User user, String oldPass, String newPass, boolean trustAllCerts)
            throws java.io.IOException, NamingException {
        LdapContext context = getConnection(user.getUsername(), oldPass);
        String dn = user.getName();

        //Switch to SSL/TLS
        StartTlsResponse tls = null;
        try {
            tls = (StartTlsResponse) context.extendedOperation(new StartTlsRequest());
        } catch (Exception e) {
            //"Problem creating object: javax.naming.ServiceUnavailableException: [LDAP: error code 52 - 00000000: LdapErr: DSID-0C090E09, comment: Error initializing SSL/TLS, data 0, v1db0"
            throw new java.io.IOException("Failed to establish SSL connection to the Domain Controller. Is LDAPS enabled?");
        }

        //Exchange certificates
        if (trustAllCerts) {
            tls.setHostnameVerifier(DO_NOT_VERIFY);
            SSLSocketFactory sf = null;
            try {
                SSLContext sc = SSLContext.getInstance("TLS");
                sc.init(null, TRUST_ALL_CERTS, null);
                sf = sc.getSocketFactory();
            } catch (java.security.NoSuchAlgorithmException e) {
                Logger.getLogger(ActiveDirectory.class.getName()).log(Level.SEVERE, null, e);
            } catch (KeyManagementException ex) {
                Logger.getLogger(ActiveDirectory.class.getName()).log(Level.SEVERE, null, ex);
            }
            tls.negotiate(sf);
        } else {
            tls.negotiate();
        }

        //Change password
        try {
            ModificationItem[] modificationItems = new ModificationItem[2];
            modificationItems[0] = new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute("unicodePwd", getPassword(oldPass)));
            modificationItems[1] = new ModificationItem(DirContext.ADD_ATTRIBUTE, new BasicAttribute("unicodePwd", getPassword(newPass)));
            context.modifyAttributes(dn, modificationItems);
        } catch (javax.naming.directory.InvalidAttributeValueException e) {
            String error = e.getMessage().trim();
            if (error.startsWith("[") && error.endsWith("]")) {
                error = error.substring(1, error.length() - 1);
            }
            System.err.println(error);
            tls.close();
            throw new NamingException(
                    "New password does not meet Active Directory requirements. "
                            + "Please ensure that the new password meets password complexity, "
                            + "length, minimum password age, and password history requirements."
            );
        } catch (NamingException e) {
            tls.close();
            throw e;
        }

        //Close the TLS/SSL session
        tls.close();
    }


    private static final HostnameVerifier DO_NOT_VERIFY =
            (final String hostname, final SSLSession session) -> true;


    private final TrustManager[] TRUST_ALL_CERTS = new TrustManager[]{
            new X509TrustManager() {
                @Override
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                @Override
                public void checkClientTrusted(
                        final java.security.cert.X509Certificate[] certs,
                        final String authType) {
                }

                @Override
                public void checkServerTrusted(
                        final java.security.cert.X509Certificate[] certs,
                        final String authType) {
                }
            }
    };

    private byte[] getPassword(final String newPass) {
        String quotedPassword = "\"" + newPass + "\"";
        char unicodePwd[] = quotedPassword.toCharArray();
        byte pwdArray[] = new byte[unicodePwd.length * 2];
        for (int i = 0; i < unicodePwd.length; i++) {
            pwdArray[i * 2 + 1] = (byte) (unicodePwd[i] >>> 8);
            pwdArray[i * 2 + 0] = (byte) (unicodePwd[i] & 0xff);
        }
        return pwdArray;
    }
}