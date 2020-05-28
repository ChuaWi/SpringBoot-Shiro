package com.cw.shiro.config;

import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.handler.SimpleMappingExceptionResolver;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

@Configuration
public class ShiroConfig {
	@Bean
	public ShiroFilterFactoryBean shirFilter(SecurityManager securityManager) {
		System.out.println("ShiroConfig.shirFilter()");
		ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
		shiroFilterFactoryBean.setSecurityManager(securityManager);
		// 拦截器
		Map<String,String> filterChainDefinitionMap = new LinkedHashMap<String,String>();
		// 配置不会被拦截的链接，顺序判断
		filterChainDefinitionMap.put("/static/**", "anon");
		// 配置退出过滤器,其中的具体的退出代码Shiro已经替我们实现了
		filterChainDefinitionMap.put("/logout", "logout");
		// 过滤链定义，从上向下顺序执行，一般将/**放在最为下边
		// authc:所有url都必须认证通过才可以访问 anon:所有url都都可以匿名访问
		filterChainDefinitionMap.put("/**", "authc");
		// 如果不设置，默认会自动寻找Web工程根目录下的"/login.jsp"页面
		shiroFilterFactoryBean.setLoginUrl("/login");
		// 登录成功后要跳转的链接
		shiroFilterFactoryBean.setSuccessUrl("/index");
		// 未授权页面;
		shiroFilterFactoryBean.setUnauthorizedUrl("/403");
		shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
		return shiroFilterFactoryBean;
	}

	/**
	 * 凭证匹配器
	 * （由于我们的密码校验交给Shiro的SimpleAuthenticationInfo进行处理了）
	 * @return
	 */

	// 因为我们的密码是加过密的，所以，如果要Shiro验证用户身份的话，需要告诉它我们用的是md5加密的，并且是加密了两次。
	// 同时我们在自己的Realm中也通过SimpleAuthenticationInfo返回了加密时使用的盐。
	// 这样Shiro就能顺利的解密密码并验证用户名和密码是否正确了。
	@Bean
	public HashedCredentialsMatcher hashedCredentialsMatcher(){
		HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
		hashedCredentialsMatcher.setHashAlgorithmName("md5");//散列算法:这里使用MD5算法;
		hashedCredentialsMatcher.setHashIterations(2);//散列的次数，比如散列两次，相当于 md5(md5(""));
		return hashedCredentialsMatcher;
	}

	@Bean
	public MyShiroRealm myShiroRealm(){
		MyShiroRealm myShiroRealm = new MyShiroRealm();
		myShiroRealm.setCredentialsMatcher(hashedCredentialsMatcher());// 设置解密规则
		return myShiroRealm;
	}

	// SecurityManager是Shiro架构的核心，通过它来链接Realm和用户(文档中称之为Subject.)
	@Bean
	public SecurityManager securityManager(){
		DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
		securityManager.setRealm(myShiroRealm());
		return securityManager;
	}

	/**
	 * 开启shiro aop注解支持.
	 * 使用代理方式;所以需要开启代码支持;
	 * @param securityManager
	 * @return
	 */
	@Bean
	public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager){
		AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
		authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
		return authorizationAttributeSourceAdvisor;
	}

	@Bean(name="simpleMappingExceptionResolver")
	public SimpleMappingExceptionResolver
	createSimpleMappingExceptionResolver() {
		SimpleMappingExceptionResolver r = new SimpleMappingExceptionResolver();
		Properties mappings = new Properties();
		mappings.setProperty("DatabaseException", "databaseError");//数据库异常处理
		mappings.setProperty("UnauthorizedException","403");
		r.setExceptionMappings(mappings);  // None by default
		r.setDefaultErrorView("error");    // No default
		r.setExceptionAttribute("ex");     // Default is "exception"
		//r.setWarnLogCategory("example.MvcLogger");     // No default
		return r;
	}
}