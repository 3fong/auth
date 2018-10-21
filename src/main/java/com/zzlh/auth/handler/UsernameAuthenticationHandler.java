package com.zzlh.auth.handler;

import java.math.BigDecimal;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Map;

import javax.security.auth.login.AccountLockedException;
import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.FailedLoginException;
import javax.servlet.http.HttpServletRequest;
import javax.sql.DataSource;

import org.apereo.cas.authentication.AuthenticationHandlerExecutionResult;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.PreventedException;
import org.apereo.cas.authentication.UsernamePasswordCredential;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.services.ServicesManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.zzlh.auth.credential.CaCredential;
import com.zzlh.auth.util.AssitUtil;
import com.zzlh.auth.util.ShaMessageDigest;

import lombok.extern.slf4j.Slf4j;

/**
 * A JDBC querying handler that will pull back the password and
 * the private salt value for a user and validate the encoded
 * password using the public salt value. Assumes everything
 * is inside the same database table. Supports settings for
 * number of iterations as well as private salt.
 * <p>
 * This handler uses the hashing method defined by Apache Shiro's
 * {@link org.apache.shiro.crypto.hash.DefaultHashService}. Refer to the Javadocs
 * to learn more about the behavior. If the hashing behavior and/or configuration
 * of private and public salts does nto meet your needs, a extension can be developed
 * to specify alternative methods of encoding and digestion of the encoded password.
 * </p>
 *
 * @author Misagh Moayyed
 * @author Charles Hasegawa
 * @since 4.1.0
 */
@Slf4j
public class UsernameAuthenticationHandler extends AbstractJdbcUsernamePasswordAuthenticationHandler {
	@Autowired
	private PasswordRetryHandlerInterceptor passwordRetryHandlerInterceptor;
	private int expired=180;
	private String callback;
	
    protected String algorithmName;
    protected String sql;
    // 密码字段
    protected String passwordFieldName;
    // 盐字段
    protected String saltFieldName;
    // 自定义盐
    protected String staticSalt;
    
	public UsernameAuthenticationHandler(String name, ServicesManager servicesManager,
			PrincipalFactory principalFactory, Integer order, DataSource dataSource, String algorithmName, String sql,
			String passwordFieldName, String saltFieldName, String staticSalt) {
		super(name, servicesManager, principalFactory, order, dataSource);
		this.algorithmName = algorithmName;
		this.sql = sql;
		this.passwordFieldName = passwordFieldName;
		this.saltFieldName = saltFieldName;
		this.staticSalt = staticSalt;
	}

	@Override
    public boolean supports(Credential credential) {
        if(credential instanceof CaCredential) {
            return !"2".equals(((CaCredential)credential).getType());
        }
        return super.supports(credential);
    }
    
    @Override
    protected AuthenticationHandlerExecutionResult authenticateUsernamePasswordInternal(
    		final UsernamePasswordCredential transformedCredential,final String originalPassword)
        throws GeneralSecurityException, PreventedException {
    	HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes())
                .getRequest();
    	passwordRetryHandlerInterceptor.vaildTime(request);
    	
        final String username = transformedCredential.getUsername();
        try {
        	
            final Map<String, Object> values = getJdbcTemplate().queryForMap(this.sql, new Object[] {username,username,username});
            
            final String oldPassword = ShaMessageDigest.encode(originalPassword, null);
            final String saltPassword = ShaMessageDigest.encode(originalPassword, staticSalt);
            final String id = (String) values.get("ID");
            final String dbPassword = (String) values.get(this.passwordFieldName);
            final BigDecimal lastUpdateTime = (BigDecimal) values.get("SCMMXGSJ");
            if (!dbPassword.equals(oldPassword) && !dbPassword.equals(saltPassword)) {
            	passwordRetryHandlerInterceptor.countTime(request);
            	log.error("密码不正确!");
                throw new FailedLoginException("Password does not match value on record.");
            }
            if( (AssitUtil.getDatePoor(new Date(),AssitUtil.convertDate(lastUpdateTime))>expired) || AssitUtil.isSimple(originalPassword)){
                request.setAttribute("id",id);
                request.setAttribute("username",username);
                request.setAttribute("callback",callback);
                log.error("账户过期!");
                throw new AccountLockedException("account expired");
            }
            return createHandlerResult(transformedCredential, this.principalFactory.createPrincipal(username), new ArrayList<>(0));

        } catch (final IncorrectResultSizeDataAccessException e) {
            if (e.getActualSize() == 0) {
            	log.error("{} 账户不存在!",username);
                throw new AccountNotFoundException(username + " not found with SQL query");
            }
            log.error("{} 有多个记录!",username);
            throw new FailedLoginException("Multiple records found for " + username);
        } catch (final DataAccessException e) {
        	log.error("SQL执行异常!{}",e);
            throw new PreventedException("SQL exception while executing query for " + username, e);
        }
    }

}
