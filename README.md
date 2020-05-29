# SpringBoot整合Shiro实现登录认证和权限授权
Shiro是一个功能强大、灵活的，开源的安全框架，主要可以帮助我们解决程序开发中认证和权限等问题。基于拦截器做的权限系统，权限控制的粒度有限，为了方便各种各样的常用的权限管理需求的实现，我们有必要使用比较好的安全框架。

> 早期Spring  security 作为一个比较完善的安全框架比较火，但是Springsecurity学习成本比较高，于是就出现了shiro安全框架，学习成本降低了很多，而且基本的功能也比较完善。

**Shiro的架构**

1、<code>Subject</code>：主题。被验证的对象，一般指的当前用户对象。但是不仅仅可以指当前用户对象，还可以是其他东西，线程等等。spring mvc中一个一个的用户的请求。

2、<code>SecurityManager</code>：安全认证管理器。是shiro的核心，会在安全认证管理器中所做所有的认证操作。类似于之前Spring MVC中的前端控制器（DispacherServlet）。

3、<code>Realm</code>：域的意思。负责访问安全认证数据。shiro框架并不存在安全认证数据，安全认证数据需要用户自己存储。shiro支持很多的Realm实现，也就是说安全认证数据我们可以放到数据库中，也可以放到文件中等等。可以把realm理解为以前web项目的dao层。

**Shiro的功能**

> 1、Authentication：身份认证/登陆，验证用户是不是拥有相对应的身份，通常被称为用户“登录”；

> 2、Authorization：授权，即权限验证，验证某个已认证的用户是否拥有某个权限；即判断用户是否能做事情，常见的如：验证某个用户是否拥有某个角色。或者粒度的验证某个用户对某个资源是否具有权限；

> 3、Session Manager：会话管理，即用户登陆后就是一次会话，在没有退出之前，它的所有信息都在会话中；会话可以是普通JavaSE环境的，也可以是Web环境的；

> 4、Cryptographt：加密，保护数据，如密码加密存储到数据库，而不是明文存储； 

> 5、Web Support：Web支持，可以保护 Web 应用程序的安全；

> 6、Caching：缓存，比如用户登陆后，其用户信息、拥有的角色/权限不必每次去查，这样提高效率；

> 7、Concurrency：多线程应用的并发验证，即如在一个线程中开启另一个线程，能把权限自动传播过去；

> 8、Testing：支持单元测试和集成测试，确保代码和预想的一样安全； 

> 9、Run As：允许一个用户假装另一个用户（如果我们允许）的身份进行访问； 

> 10、Remember Me：记住我，这个是非常常见的功能，即一次登陆后，下次再来的话不用登陆了。

## SpringBoot整合Shiro实现登录认证和权限授权步骤

**1.引入shiro、jpa、thymeleaf等依赖**

```java
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-spring</artifactId>
    <version>1.4.0</version>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-thymeleaf</artifactId>
</dependency>
```
**2.application.yml配置文件，添加datasource、jpa、thymeleaf相关配置**

```java
spring:
    datasource:
      url: jdbc:mysql://localhost:3306/test?useSSL=false&useUnicode=true&characterEncoding=UTF-8&serverTimezone=UTC
      username: root
      password: 123456
      #schema: database/import.sql
      #sql-script-encoding: utf-8
      driver-class-name: com.mysql.cj.jdbc.Driver

    jpa:
      database: mysql
      show-sql: true
      hibernate:
        ddl-auto: update
      properties:
         hibernate:
            dialect: org.hibernate.dialect.MySQL5Dialect

    thymeleaf:
       cache: false
       mode: HTML
```
thymeleaf的配置是为了去掉html的校验
**3.新建6个页面用来测试**

 - index.html ：首页 
 - login.html ：登录页 
 - userInfo.html ： 用户信息页面
 - userInfoAdd.html ：添加用户页面 
 - userInfoDel.html ：删除用户页面
 - 403.html ： 没有权限的页面
 
**4.采用 Jpa 技术来自动生成基础数据库表格，对应的实体如下：**
 - 用户信息

```java
@Entity
public class UserInfo implements Serializable {
    @Id
    @GeneratedValue
    private Integer uid; // 用户ID
    @Column(unique =true)
    private String username; // 帐号
    private String name; // 名称
    private String password; // 密码
    private String salt; // 密码盐
    private byte state; // 用户状态
    // 0:创建未认证（比如没有激活，没有输入验证码等等）--等待验证的用户
    // 1:正常状态，2：用户被锁定
    @ManyToMany(fetch= FetchType.EAGER) // 立即从数据库中进行加载数据
    @JoinTable(name = "SysUserRole", joinColumns = { @JoinColumn(name = "uid") }, inverseJoinColumns ={@JoinColumn(name = "roleId") })
    private List<SysRole> roleList; // 一个用户具有多个角色
    // 省略 get set 方法
}
```

 - 角色信息

```java
@Entity
public class SysRole {
    @Id
    @GeneratedValue
    private Integer id; // 编号
    private String role; // 角色标识程序中判断使用,如"admin",这个是唯一的
    private String description; // 角色描述，UI界面显示使用
    private Boolean available = Boolean.FALSE; // 是否可用，如果不可用将不会添加给用户

    // 角色 - 权限关系：多对多关系
    @ManyToMany(fetch= FetchType.EAGER)
    @JoinTable(name="SysRolePermission",joinColumns={@JoinColumn(name="roleId")},inverseJoinColumns={@JoinColumn(name="permissionId")})
    private List<SysPermission> permissions;

    // 用户 - 角色关系定义
    @ManyToMany
    @JoinTable(name="SysUserRole",joinColumns={@JoinColumn(name="roleId")},inverseJoinColumns={@JoinColumn(name="uid")})
    private List<UserInfo> userInfos; // 一个角色对应多个用户
	// 省略 get set 方法
}
```

 - 权限信息

```java
@Entity
public class SysPermission implements Serializable {
    @Id
    @GeneratedValue
    private Integer id; // 主键
    private String name; // 名称
    @Column(columnDefinition="enum('menu','button')")
    private String resourceType; // 资源类型，[menu|button]
    private String url; // 资源路径
    private String permission; // 权限字符串
    // menu例子：role:*，button例子：role:create,role:update,role:delete,role:view
    private Long parentId; // 父编号
    private String parentIds; // 父编号列表
    private Boolean available = Boolean.FALSE;
    @ManyToMany
    @JoinTable(name="SysRolePermission",joinColumns={@JoinColumn(name="permissionId")},inverseJoinColumns={@JoinColumn(name="roleId")})
    private List<SysRole> roles;
    // 省略 get set 方法
}
```
启动项目，以上的代码会自动生成 <code>user_info</code>（用户信息表）、 <code>sys_role </code>（角色信息表）、 <code>sys_permission </code>（权限信息表）、 <code>sys_user_role </code>（用户角色表）、 <code>sys_role_permission </code>（角色权限表）这五张表。

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200528124949940.png)

**5.给这五张表插入一些初始化数据<code>shiro_user.sql</code>**

```java
INSERT INTO `user_info` (`uid`,`username`,`name`,`password`,`salt`,`state`) VALUES ('1', 'admin', '管理员', 'd3c59d25033dbf980d29554025c23a75', '8d78869f470951332959580424d4bf4f', 0);
INSERT INTO `sys_role` (`id`,`available`,`description`,`role`) VALUES (1,0,'管理员','admin');
INSERT INTO `sys_role` (`id`,`available`,`description`,`role`) VALUES (2,0,'VIP会员','vip');
INSERT INTO `sys_role` (`id`,`available`,`description`,`role`) VALUES (3,1,'test','test');
INSERT INTO `sys_permission` (`id`,`available`,`name`,`parent_id`,`parent_ids`,`permission`,`resource_type`,`url`) VALUES (1,0,'用户管理',0,'0/','userInfo:view','menu','userInfo/userList');
INSERT INTO `sys_permission` (`id`,`available`,`name`,`parent_id`,`parent_ids`,`permission`,`resource_type`,`url`) VALUES (2,0,'用户添加',1,'0/1','userInfo:add','button','userInfo/userAdd');
INSERT INTO `sys_permission` (`id`,`available`,`name`,`parent_id`,`parent_ids`,`permission`,`resource_type`,`url`) VALUES (3,0,'用户删除',1,'0/1','userInfo:del','button','userInfo/userDel');
INSERT INTO `sys_user_role` (`role_id`,`uid`) VALUES (1,1);
INSERT INTO `sys_role_permission` (`permission_id`,`role_id`) VALUES (1,1);
INSERT INTO `sys_role_permission` (`permission_id`,`role_id`) VALUES (2,1);
INSERT INTO `sys_role_permission` (`permission_id`,`role_id`) VALUES (3,2);
```
**6.自定义配置ShiroConfig类**

Apache Shiro 核心通过 Filter 来实现，就好像SpringMvc 通过DispachServlet 来主控制一样。既然是使用 Filter 一般也就能猜到，是通过URL规则来进行过滤和权限校验，所以我们需要定义一系列关于URL的规则和访问权限。

```java
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
		// 过滤链定义，从上向下顺序执行，一般将"/**"/放在最为下边
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
```
**7.Realm类，实现认证与授权**

<code>Realm</code>是专用于安全框架的 DAO. Shiro 的认证过程,最终会交由 Realm 执行，这时会调用 Realm 的getAuthenticationInfo(token)方法。通过它来验证用户身份和权限。只需要从我们的数据源中把用户和用户的角色权限信息取出来交给Shiro即可。

该方法主要执行以下操作:
 - 检查提交的进行认证的令牌信息
 - 根据令牌信息从数据源(通常为数据库)中获取用户信息
 - 对用户信息进行匹配验证
 - 验证通过将返回一个封装了用户信息的AuthenticationInfo实例
 - 验证失败则抛出AuthenticationException异常信息

我们要做的就是自定义一个 Realm 类，继承AuthorizingRealm 抽象类，重载<code>doGetAuthenticationInfo()</code>，重写获取用户信息的方法。

```java
public class MyShiroRealm extends AuthorizingRealm {
    @Resource
    private UserInfoService userInfoService;
    
    //主要是用来进行身份认证的，验证用户输入的账号和密码是否正确
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token)
            throws AuthenticationException {
        System.out.println("MyShiroRealm.doGetAuthenticationInfo()");
        //获取用户的输入的账号
        String username = (String)token.getPrincipal();
        System.out.println(token.getCredentials());
        //通过username从数据库中查找 User对象
        //实际项目中，这里可以根据实际情况做缓存，如果不做，Shiro自己也是有时间间隔机制，2分钟内不会重复执行该方法
        UserInfo userInfo = userInfoService.findByUsername(username);
        System.out.println("----->>userInfo="+userInfo);
        if(userInfo == null){
            return null;
        }
        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(
                userInfo, //用户名
                userInfo.getPassword(), //密码
                ByteSource.Util.bytes(userInfo.getCredentialsSalt()),//salt=username+salt
                getName()  //realm name
        );
        return authenticationInfo;
    }

    //主要是对用户角色权限进行控制
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        System.out.println("权限配置-->MyShiroRealm.doGetAuthorizationInfo()");
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        UserInfo userInfo  = (UserInfo)principals.getPrimaryPrincipal();
        for(SysRole role:userInfo.getRoleList()){
            authorizationInfo.addRole(role.getRole());
            for(SysPermission p:role.getPermissions()){
                authorizationInfo.addStringPermission(p.getPermission());
            }
        }
        return authorizationInfo;
    }
}
```
Shiro 的权限授权是通过继承AuthorizingRealm抽象类，重载<code>doGetAuthorizationInfo()</code>。当访问到页面的时候，链接配置了相应的权限或者 Shiro 标签才会执行此方法，否则不会执行。在这个方法中主要是使用类：<code>SimpleAuthorizationInfo</code>进行角色和权限的添加。

<code>authorizationInfo.addRole()</code>**是添加角色的方法**

<code>authorizationInfo.addStringPermission()</code>**是添加权限的方法**

这里可以使用Java8函数式编程，代替foreach循环

```java
sysRoleMapper.findRoleByUsername(userInfo.getUsername()).stream().forEach(
        sysRole -> {
            authorizationInfo.addRole(sysRole.getRole());
            sysPermissionMapper.findPermissionByRoleId(sysRole.getId()).stream().forEach(
                    sysPermission -> {
                        authorizationInfo.addStringPermission(sysPermission.getPermission());
                    }
            );
        }
);
```
**8.权限操作的接口**

```java
@Controller
@RequestMapping("/userInfo")
public class UserInfoController {
    /**
     * 用户查询
     * @return
     */
    @RequestMapping("/userList")
    @RequiresPermissions("userInfo:view")
    public String userInfo(){
        return "userInfo";
    }
    /**
     * 用户添加
     * @return
     */
    @RequestMapping("/userAdd")
    @RequiresPermissions("userInfo:add")
    public String userInfoAdd(){
        return "userInfoAdd";
    }
    /**
     * 用户删除
     * @return
     */
    @RequestMapping("/userDel")
    @RequiresPermissions("userInfo:del")
    public String userDel(){
        return "userInfoDel";
    }
}
```
**9.登录实现**

```java
@Controller
public class HomeController {

    @RequestMapping({"/","/index"})
    public String index(){
        return"/index";
    }

    @RequestMapping("/login")
    public String login(HttpServletRequest request, Map<String, Object> map) throws Exception{
        System.out.println("HomeController.login()");
        // 登录失败从request中获取shiro处理的异常信息
        // shiroLoginFailure:就是shiro异常类的全类名
        String exception = (String) request.getAttribute("shiroLoginFailure");
        System.out.println("exception=" + exception);
        String msg = "";
        if (exception != null) {
            if (UnknownAccountException.class.getName().equals(exception)) {
                System.out.println(" -- > 账号不存在");
                msg = " -- > 账号不存在";
            } else if (IncorrectCredentialsException.class.getName().equals(exception)) {
                System.out.println(" -- > 密码不正确");
                msg = " -- > 密码不正确";
            } else {
                msg = "else >> "+exception;
                System.out.println("else -- >" + exception);
            }
        }
        map.put("msg", msg);
        // 此方法不处理登录成功,由shiro进行处理
        return "/login";
    }

    @RequestMapping("/403")
    public String unauthorizedRole(){
        System.out.println("------没有权限-------");
        return "403";
    }
}
```
**下面进行测试，启动项目**

访问<code>http://localhost:8080/userInfo/userList</code>页面

由于没有登录就会跳转到<code>http://localhost:8080/login</code>页面

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200528153528747.png)

登录后，访问就会看到用户信息

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200528153658141.png)

上面操作触发MyShiroRealm.doGetAuthenticationInfo()这个方法，也就是登录认证。
访问<code>http://127.0.0.1:8080/userInfo/userAdd</code>显示用户添加界面

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200528154013504.png)

访问<code>http://127.0.0.1:8080/userInfo/userDel</code>显示403没有权限

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200528154032228.png)

上面操作触发MyShiroRealm.doGetAuthorizationInfo()这个方法，也就是权限授权。
可以修改用户admin不同权限进行测试。
以上完成Shiro实现登录认证和权限授权的功能。

点击这里>[CSDN项目博客地址-SpringBoot整合Shiro实现登录认证和权限授权](https://blog.csdn.net/weixin_44316527/article/details/106402304)

点击这里>[Github项目源码地址-SpringBoot整合Shiro实现登录认证和权限授权](https://github.com/ChuaWi/SpringBoot-Shiro)

[学习网址：SpringBoot整合Shiro-登录认证和权限管理](http://www.ityouknow.com/springboot/2017/06/26/spring-boot-shiro.html)
