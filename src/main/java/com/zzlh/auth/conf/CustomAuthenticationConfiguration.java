package com.zzlh.auth.conf;

import org.apereo.cas.authentication.AuthenticationEventExecutionPlan;
import org.apereo.cas.authentication.AuthenticationEventExecutionPlanConfigurer;
import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.authentication.principal.DefaultPrincipalFactory;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.configuration.model.support.jdbc.JdbcAuthenticationProperties;
import org.apereo.cas.configuration.model.support.jdbc.QueryEncodeJdbcAuthenticationProperties;
import org.apereo.cas.configuration.support.JpaBeans;
import org.apereo.cas.services.ServicesManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.zzlh.auth.handler.CaAuthenticationHandler;
import com.zzlh.auth.handler.PasswordRetryHandlerInterceptor;
import com.zzlh.auth.handler.UsernameAuthenticationHandler;


/**
 * 参考 {@link org.apereo.cas.web.flow.config.CasWebflowContextConfiguration}
 *  DefaultLoginWebflowConfigurer
 */
@Configuration("CustomAuthenticationConfiguration")
@EnableConfigurationProperties(CasConfigurationProperties.class)
public class CustomAuthenticationConfiguration implements AuthenticationEventExecutionPlanConfigurer {
	
	@Autowired
    private CasConfigurationProperties casProperties;
    @Autowired
    @Qualifier("servicesManager")
    private ServicesManager servicesManager;
    
    @Bean
    public PasswordRetryHandlerInterceptor getPasswordRetryHandlerInterceptor() {
    	return new PasswordRetryHandlerInterceptor();
    }
    
    /**
     * @Description cas登录认证
     * @return
     */
    @Bean
    public AuthenticationHandler customAuthenticationHandler() {
    	final JdbcAuthenticationProperties jdbc = casProperties.getAuthn().getJdbc();
        QueryEncodeJdbcAuthenticationProperties param = jdbc.getEncode().get(0);
    	UsernameAuthenticationHandler handler = new UsernameAuthenticationHandler(param.getName(),
    			servicesManager,new DefaultPrincipalFactory(),param.getOrder(),
    			JpaBeans.newDataSource(param),param.getAlgorithmName(),param.getSql(),
    			param.getPasswordFieldName(),param.getSaltFieldName(),param.getStaticSalt());
        return handler;
    }
    
    /**
     * @Description ca登录认证
     * @return
     */
    @Bean
    public AuthenticationHandler caAuthenticationHandler() {
    	final JdbcAuthenticationProperties jdbc = casProperties.getAuthn().getJdbc();
        QueryEncodeJdbcAuthenticationProperties param = jdbc.getEncode().get(1);
        CaAuthenticationHandler handler = new CaAuthenticationHandler(param.getName(),
    			servicesManager,new DefaultPrincipalFactory(),param.getOrder(),
    			JpaBeans.newDataSource(param),param.getSql());
        return handler;
    }
    
    /**
     * @Description 注册验证器
     * @return
     */
    @Override
    public void configureAuthenticationExecutionPlan(AuthenticationEventExecutionPlan plan) {
        plan.registerAuthenticationHandler(customAuthenticationHandler());
        plan.registerAuthenticationHandler(caAuthenticationHandler());
    }
    
}
