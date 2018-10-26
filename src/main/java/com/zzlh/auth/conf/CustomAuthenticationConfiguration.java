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
import org.apereo.cas.web.flow.CasWebflowConfigurer;
import org.apereo.cas.web.flow.CasWebflowExecutionPlan;
import org.apereo.cas.web.flow.CasWebflowExecutionPlanConfigurer;
import org.apereo.cas.web.flow.config.CasWebflowContextConfiguration;
import org.apereo.cas.web.flow.configurer.DefaultLoginWebflowConfigurer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.webflow.definition.registry.FlowDefinitionRegistry;
import org.springframework.webflow.engine.builder.support.FlowBuilderServices;

import com.zzlh.auth.handler.CaAuthenticationHandler;
import com.zzlh.auth.handler.PasswordRetryHandlerInterceptor;
import com.zzlh.auth.handler.UsernameAuthenticationHandler;


/**
 * 参考 {@link org.apereo.cas.web.flow.config.CasWebflowContextConfiguration}
 *  DefaultLoginWebflowConfigurer
 */
@Configuration("CustomAuthenticationConfiguration")
@EnableConfigurationProperties(CasConfigurationProperties.class)
public class CustomAuthenticationConfiguration extends CasWebflowContextConfiguration implements AuthenticationEventExecutionPlanConfigurer   {
	
	@Autowired
    private CasConfigurationProperties casProperties;
    @Autowired
    @Qualifier("servicesManager")
    private ServicesManager servicesManager;
    @Autowired
    private ApplicationContext applicationContext;
    
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
 
    @ConditionalOnMissingBean(name = "defaultWebflowConfigurer")
    @Bean
    @Order(0)
    @RefreshScope
    @Override
    public CasWebflowConfigurer defaultWebflowConfigurer() {
        final CustomLoginWebflowConfigurer c = new CustomLoginWebflowConfigurer(builder(), loginFlowRegistry(), applicationContext, casProperties);
        c.setLogoutFlowDefinitionRegistry(logoutFlowRegistry());
        c.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return c;
    }
}
