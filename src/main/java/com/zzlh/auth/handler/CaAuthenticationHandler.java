package com.zzlh.auth.handler;

import java.security.GeneralSecurityException;
import java.util.ArrayList;

import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.FailedLoginException;
import javax.servlet.http.HttpServletRequest;
import javax.sql.DataSource;
import javax.validation.constraints.NotNull;

import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.adaptors.jdbc.AbstractJdbcUsernamePasswordAuthenticationHandler;
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

import lombok.extern.slf4j.Slf4j;

/**
 * 自定义验证处理器 主要用来完成CA key验证工作
 *
 * Created by Sofar on 2016-04-08.
 */
@Slf4j
public class CaAuthenticationHandler extends AbstractJdbcUsernamePasswordAuthenticationHandler {
	@Autowired
	private PasswordRetryHandlerInterceptor passwordRetryHandlerInterceptor;

	public CaAuthenticationHandler(String name, ServicesManager servicesManager, PrincipalFactory principalFactory,
			Integer order, DataSource dataSource, String sql) {
		super(name, servicesManager, principalFactory, order, dataSource);
		this.sql = sql;
	}

	@NotNull
	private String sql;

	@Override
	public boolean supports(Credential credential) {
		if (credential instanceof CaCredential) {
			return "2".equals(((CaCredential) credential).getType());
		}
		return super.supports(credential);
	}

	@Override
	protected final AuthenticationHandlerExecutionResult authenticateUsernamePasswordInternal(
			UsernamePasswordCredential credential, String originalPassword)
			throws GeneralSecurityException, PreventedException {
		HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes())
				.getRequest();
		passwordRetryHandlerInterceptor.vaildTime(request);
		// 将凭证对象转化为CA凭证对象
		CaCredential caCredential = (CaCredential) credential;
		// 获取CA KEY.ID
		final String caId = caCredential.getUsername();
		String username = null;
		try {
			username = getJdbcTemplate().queryForObject(sql, String.class, caId);
			if (username == null) {
				passwordRetryHandlerInterceptor.countTime(request);
				log.error("caId {} 不存在", caId);
				throw new FailedLoginException("no records found for caID [" + caId + "]");
			}
		} catch (final IncorrectResultSizeDataAccessException e) {
			if (e.getActualSize() == 0) {
				log.error("{} 用户不存在", username);
				throw new AccountNotFoundException(username + " not found with SQL query");
			} else {
				log.error("{} 用户有多条记录", username);
				throw new FailedLoginException("Multiple records found for " + username);
			}
		} catch (final DataAccessException e) {
			log.error("SQL执行异常 {}", e);
			throw new PreventedException("SQL exception while executing query for " + username, e);
		}
		credential.setUsername(username);
		return createHandlerResult(credential, this.principalFactory.createPrincipal(username), new ArrayList<>(0));
	}

	@Override
	protected AuthenticationHandlerExecutionResult doAuthentication(final Credential credential)
			throws GeneralSecurityException, PreventedException {
		final CaCredential caCredential = (CaCredential) credential;
		if (StringUtils.isBlank(caCredential.getUsername())) {
			log.error("用户名为空!");
			throw new AccountNotFoundException("用户名为空!");
		}
		return authenticateUsernamePasswordInternal(caCredential, caCredential.getPassword());
	}
}
