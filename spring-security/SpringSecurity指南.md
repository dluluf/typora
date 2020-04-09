# Spring-Security



## 架构

![spring-security-architecture](https://img-blog.csdnimg.cn/20200409182752249.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzI1NzE5Njg5,size_16,color_FFFFFF,t_70)

### 说明

#### Servlet Filter

Spring-Security 安全处理是基于Servlet Filter 来实现的。

这里通过添加一个代理Filter(`DelegatingFilterProxy`),这个Filter的名称一般定义为`springSecurityFilterChain`,它的实现类就是`FilterChainProxy`。

#### FilterChainProxy

<font color="red" >`FilterChainProxy` </font> 管理了所有的`SecurityFilterChain` 集合，这里``SecurityFilterChain` `是一个接口，

默认的实现有`DefaultSecurityFilterChain`。

`FilterChainProxy`  会根据请求的URL来判断使用哪一个 `SecurityFilterChain` 。这里注意，spring-security对某一个请求，<font color="red" >**只会使用一个** </font>`SecurityFilterChain` 来处理。

#### SecurityFilter

对于每一个SecurityFilter,都有自己的处理逻辑。

有的则需要去处理认证的逻辑，例如`UsernamePasswordAuthenticationFilter` ,

它需要对登入页面输入的用户名和密码进行认证处理。不过这里它是通过认证组件`authenticationManager` 

组件来实现的。

#### ProviderManager

是`authenticationManager` 的默认实现。它通过维护一组`authenticationProvider`来实现具体的认证逻辑。





## Security 一些重要组件

### SecurityContextHolder

认证成功后的信息由Holder通过TheadLocal机制（当然在不同的场景中，这里可以切换到别的方式），保存在SecurityContext中。

### Authentication  

`Authentication`:请求用户是谁

The `Authentication` contains:

- `principal` - identifies the user. When authenticating with a username/password this is often an instance of [`UserDetails`](https://docs.spring.io/spring-security/site/docs/5.3.1.RELEASE/reference/html5/#servlet-authentication-userdetails).
- `credentials` - Often a password. In many cases this will be cleared after the user is authenticated to ensure it is not leaked.
- `authorities` - the [`GrantedAuthority`s](https://docs.spring.io/spring-security/site/docs/5.3.1.RELEASE/reference/html5/#servlet-authentication-granted-authority) are high level permissions the user is granted. A few examples are roles or scopes.



```java
//认证统一接口
public interface AuthenticationManager {
	//认证处理入口
  Authentication authenticate(Authentication authentication)
    throws AuthenticationException;

}
```

```java
//默认实现类
public class ProviderManager implements AuthenticationManager, MessageSourceAware,
		InitializingBean {
	private List<AuthenticationProvider> providers = Collections.emptyList();
    //可以提供一个parentAuthenticationManager,就像一个总管。管理List<AuthenticationProvider>
    //后面会具体解释这个parent。
	private AuthenticationManager parent;
    //这里需要提供 AuthenticationProvider 的实例去处理具体的认证逻辑，可以是多个。       
	public ProviderManager(List<AuthenticationProvider> providers) {
		this(providers, null);
	}
	public ProviderManager(List<AuthenticationProvider> providers,
			AuthenticationManager parent) {
		Assert.notNull(providers, "providers list cannot be null");
		this.providers = providers;
		this.parent = parent;
		checkState();
	}
```

```java
//具体处理认证逻辑的抽象接口
public interface AuthenticationProvider {
        Authentication authenticate(Authentication authentication) throws AuthenticationException;
		//通过该接口，实现选择支持的认证类型
        boolean supports(Class<?> authentication);
}
```



`AuthenticationManager` 和 `AuthenticationProvider`都提供了认证接口，但是具体的处理逻辑由`AuthenticationProvider`的实例来处理，`AuthenticationManager`只作为入口。

```java
//关键代码截取
for (AuthenticationProvider provider : getProviders()) {
    if (!provider.supports(toTest)) {
        continue;
    }
    try {
        result = provider.authenticate(authentication);
        if (result != null) {
            copyDetails(authentication, result);
            break;
        }
    }
}
```

```java
public Authentication authenticate(Authentication authentication)
			throws AuthenticationException {
		Class<? extends Authentication> toTest = authentication.getClass();
		AuthenticationException lastException = null;
		Authentication result = null;
		for (AuthenticationProvider provider : getProviders()) {
			if (!provider.supports(toTest)) {
				continue;
			}
			try {
				result = provider.authenticate(authentication);
				if (result != null) {
					copyDetails(authentication, result);
					break;
				}
			}
			catch (AccountStatusException e) {
			}
		}
	}
```



#### 同时提供多种认证机制

- 如何提供多种认证机制的？

  就是通过这里的AuthenticationProvider，因为`ProviderManager`他管理了多个`AuthenticationProvider`，每一种机制可以是一个`AuthenticationProvider`的实现。

- 是否需要考虑各个认证机制的顺序？

  不需要考虑各个机制的顺序问题，因为只要一个认证通过就ok了。（代码实现是直接跳出循环）

#### Parent AuthenticationManager

> `ProviderManager`管理了一个父的`AuthenticationManager`，作为最后的兜底。就是说当所有的认证机制都无法判断的时候，即返回为空的时候，此时可以通过父类来处理。如果没有定义这个父类，是会抛出
> AuthenticationException。



>Sometimes an application has logical groups of protected resources (e.g. all web resources that match a path pattern `/api/**`), and each group can have its own dedicated `AuthenticationManager`. Often, each of those is a `ProviderManager`, and they share a parent. The parent is then a kind of "global" resource, acting as a fallback for all providers.


![authenticationManager](https://img-blog.csdnimg.cn/2020040923013720.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzI1NzE5Njg5,size_16,color_FFFFFF,t_70)






> 总结
>
> 这里的意思就是，比如api/resources1,api/resources2,api/resources3
>
> 这里都matche  api/ ** , 但是对于resources1 、 resources2、都有不同的认证处理，但是他们可以共用同一个parent ProviderManager。
>
> 这里对每个resources的处理，其实也是细化了处理过程。最初的执行链还是api/** match的那一条链，只不过在这个链下又多了更多细化的处理。



### Authoriztion (Access Control)

#### 设计原理：

AccessDecisionManager是入口，然后具体是否有权限是调用AccessDecisionVoter进行判断。

> 为什么这样设计？
>
> 因为这里`AccessDecisionManager`有三个实现：
>
> AffirmativeBased一种只要一个voter返回有权限即可。
>
> ConsensusBased大多数voter返回有权限，就说明有权限
>
> UnConsensusBased要求必须所有的voter都返回或者弃权才行。



这里decide方法被

org.springframework.security.web.access.intercept.FilterSecurityInterceptor#invoke -》

org.springframework.security.access.intercept.AbstractSecurityInterceptor#beforeInvocation

调用。

#### AccessDecisionManager:

```java
public interface AccessDecisionManager {
	void decide(Authentication authentication, Object object,
			Collection<ConfigAttribute> configAttributes) throws AccessDeniedException,
			InsufficientAuthenticationException;
	boolean supports(ConfigAttribute attribute);
	boolean supports(Class<?> clazz);
}
```

#### AccessDecisionVoter:

```java
boolean supports(ConfigAttribute attribute);

boolean supports(Class<?> clazz);
//authentication表示认证处理后，保存的认证信息
//object是需要判断是否能获取的资源
//ConfigAttribute 是用于access-control判断的信息，比如角色-url列表
int vote(Authentication authentication, S object,Collection<ConfigAttribute> attributes);
```

默认的处理类：只要返回积极响应即可

org.springframework.security.access.vote.AffirmativeBased



#### Springboot中AccessDecisionManager的创建过程

>AbstractInterceptUrlConfigurercreate->
>
>FilterSecurityInterceptor ->
>
>getAccessDecisionManager ->
>
>AffirmativeBased



#### show you the code

```java
private FilterSecurityInterceptor createFilterSecurityInterceptor(H http,
			FilterInvocationSecurityMetadataSource metadataSource,
			AuthenticationManager authenticationManager) throws Exception {
		FilterSecurityInterceptor securityInterceptor = new FilterSecurityInterceptor();
		securityInterceptor.setSecurityMetadataSource(metadataSource);
		securityInterceptor.setAccessDecisionManager(getAccessDecisionManager(http));
		securityInterceptor.setAuthenticationManager(authenticationManager);
		securityInterceptor.afterPropertiesSet();
		return securityInterceptor;
	}
```



#### Method Security





## Spring-Security实现流程

### 从 Web Filter开始

#### DelegatingFilterProxy 

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200409230431641.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzI1NzE5Njg5,size_16,color_FFFFFF,t_70)

DelegatingFilterProxy （Spring-Web） ->FilterChainProxy (Spring-Security)->

这里看出Spring是通过DelegatingFilterProxy来整合Spring-Security的

>这个类在我们的web.xml配置中使用的，当我们定义的filter为DelegatingFilterProxy，此时呢，所有的请求filter,都会去容器中找一个叫springsecurityfilterchain的bean来处理。这里是方便我们去处理web应用，当我们需要一个filter来处理，此时我们只需要在spring相关的配置文件中定义一个bean,id为`springSecurityFilterChain` ，而在web.xml中写成DelegatingFilterProxy。

DelegatingFilterProxy:不需要是一个spring 的bean,也就是说在不使用spring容器开发的应用中，可以是有该类。或者说在spring容器还没有初始化的时候，可以使用该类来处理。

DelegatingFilterProxy 把处理的执行交给了 FilterChainProxy（注意这个类是spring-security中的类，然后会有很多这样的类去做具体的filter操作），这个bean一般使用 `springSecurityFilterChain` 这个bean id来做配置。

>FilterChainProxy这里代理中包含很多的filter(关于spring-security安全认证和权限控制的filters),当然也可以是不同的filter chains,不过一个请求只会被一个filter chain处理，一般是根据请求路径来判断交给那个filter chain处理。
>这里就是我们需要关注和定义的filters

#### SecurityFilterChain接口

> spring-security可以有很多SecurityFilterChain，但是最终只有一个会被匹配。
>
> 可以用于oauth整合、jwt整合，也可以用于处理不需要安全处理的路径。
>
> **也就是说所有的链都必须实现该类**
>
> 默认的**`DefaultSecurityFilterChain`**

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200409230404505.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzI1NzE5Njg5,size_16,color_FFFFFF,t_70)

一般springboot应用中有6条filter chains,第一个是用来控制静态文件和错误页面的（可以通过配置security.ignored来定义资源路径）。

最后一个filter chain 默认会对 `/**` 进行控制（包括认证、授权、异常处理、session处理、请求头处理等等）。

默认最后一个chain有11个filters,不过一般我们不需要太关注这些filters。

##### `IgnoredPathsWebSecurityConfigurerAdapter`

```java
@Order(SecurityProperties.IGNORED_ORDER)
	private static class IgnoredPathsWebSecurityConfigurerAdapter
			implements WebSecurityConfigurer<WebSecurity> {
```

>默认的springBoot security项目中，其实对静态资源的处理和error路径的处理，使用的同一个filter chain :`IgnoredPathsWebSecurityConfigurerAdapter`，它的order 为最高的。HIGHEST_PRECEDENCE = Integer.MIN_VALUE，所以这是一个回去匹配的filter chain。



在spring-security中新增一个filter chain(其实也是覆盖的意思，比如原来的filter针对的是 /** ，这里我们写了一个/foo/** ,此时如果请求是/foo/，则只会经过该filter chain；如果是其他的请求，才会使用原来默认的chain )：

```java
@Configuration@Order(SecurityProperties.BASIC_AUTH_ORDER - 10)
public class ApplicationConfigurerAdapter extends WebSecurityConfigurerAdapter {
  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.antMatcher("/foo/**")
     ...;
  }}
```



> **注意**：
> 如果想在spring-security 的chain使用filter Bean，
>
> 1.不要通过使用@bean 方式去添加
>
> 2.如果使用FilterRegistrationBean注册filter为一个Bean,则需要显示设置其不被容器加载。
>
> 因为这两种方式都会将filter应用于整个web 容器中。
>
> 而添加自定义的security filter，需要通过 
>
> WebSecurityConfigurerAdapter#configure()
>
> WebSecurityConfigurerAdapter#init（）



### 什么时候开始进入到认证处理流程



> 其实这里是认证处理的发起Filter,当用户第一次从浏览器访问受限资源时，因为其他认证Filter只对自己关注的AuthenticationToken进行处理，也就是说第一次访问时，这些Filter是去处理的，只有这个Filter发现如果用户没有进行认证，则进行相应的处理。比如：重定向到登入页面。



#### 处理流程

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200409230525770.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzI1NzE5Njg5,size_16,color_FFFFFF,t_70)



> The `ExceptionTranslationFilter`allows translation of `AccessDeniedException` and `AuthenticationException`into HTTP responses.


- First, the `ExceptionTranslationFilter` invokes `FilterChain.doFilter(request, response)` to invoke the rest of the application.
- If the user is not authenticated or it is an `AuthenticationException`, then *Start Authentication*.
  - The SecurityContextHolder is cleared out
  - The `HttpServletRequest` is saved in the `RequestCache`. When the user successfully authenticates, the `RequestCache` is used to replay the original request.
  - The `AuthenticationEntryPoint` is used to request credentials from the client. For example, it might redirect to a login page or send a `WWW-Authenticate` header.
- Otherwise if it is an `AccessDeniedException`, then *Access Denied*. The `AccessDeniedHandler` is invoked to handle access denied.



#### show you the pseudocode

```java
try {
    filterChain.doFilter(request, response); 
} catch (AccessDeniedException | AuthenticationException e) {
    if (!authenticated || e instanceof AuthenticationException) {
        startAuthentication(); 
    } else {
        accessDenied(); 
    }
}
```



开始认证处理，从`AuthenticationEntryPoint`开始，然后调用org.springframework.security.web.AuthenticationEntryPoint#commence，具体的实现类来实现如何进行认证。



### 是否需要处理认证

当用户提交认证信息后，比如输入用户名\密码之后。

#### AbstractAuthenticationProcessingFilter

该类将会判断请求是否需要认证或者是本类实现类应该处理的认证类型。

如果是，则进行具体的认证信息判断。

##### show you pseudocode

这里以 `UsernamePasswordAuthenticationFilter`  为例：

```java
public class UsernamePasswordAuthenticationFilter extends
      AbstractAuthenticationProcessingFilter {
	//这里开始尝试进行认证信息判断
   public Authentication attemptAuthentication(HttpServletRequest request,
         HttpServletResponse response) throws AuthenticationException {
     
      String username = obtainUsername(request);
      String password = obtainPassword(request);
      UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
            username, password);
      // Allow subclasses to set the "details" property
      setDetails(request, authRequest);
       //最终调用authenticationManager去进行认证
      return this.getAuthenticationManager().authenticate(authRequest);
   }
}
```



### 真正处理用户认证信息判断

#### 认证判断

具体的认证判断由 <font color="red" >**`AuthenticationProvider`**  </font>的实现类来判断。

如之前分析，一个AuthenticationManger可以有多个`AuthenticationProvider`,每个都可以处理或者处理不了，只要有一个能判断即可，或者都判断不了，还可以通过 ParentAuthenticationManager来兜底。

#### 认证处理的结果

三种情况：

- 成功
- 不能决定
- 异常

如果返回认证异常，我们可以捕获后跳转到认证页面，比如登入页面，或者返回认证错误页面，在接口调用时，可以返回401响应等等



## SpringSecurity在SpringBoot中应用：

### 如何添加一个新链

继承`WebSecurityConfigurerAdapter`

```java
@Configuration
//顺序很重要，必须定义顺序，具体添加在那个位置根据业务情况。
@Order(SecurityProperties.BASIC_AUTH_ORDER - 10)
public class ApplicationConfigurerAdapter extends WebSecurityConfigurerAdapter {
  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.antMatcher("/foo/**")
     ...;
  }}
```

### 如何覆盖默认配置

```java
@Configuration
//顺序很重要，必须定义顺序，具体添加在那个位置根据业务情况。
@Order(SecurityProperties.BASIC_AUTH_ORDER - 10)
@EnableWebSecurity
MySecurityChainConfig extends WebSecurityConfigurerAdapter{
  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.antMatcher("/foo/**")
      .authorizeRequests()
        .antMatchers("/foo/bar").hasRole("BAR")//这里细化了对具体路径的处理
        .antMatchers("/foo/spam").hasRole("SPAM")
        .anyRequest().isAuthenticated();
  }
}
```

### 配置全局共享对象

```java
@Configuration
public class ApplicationSecurity extends WebSecurityConfigurerAdapter {
   ... // web stuff here
  @Autowired
  public void initialize(AuthenticationManagerBuilder builder, DataSource dataSource) {
    builder.jdbcAuthentication().dataSource(dataSource).withUser("dave")
      .password("secret").roles("USER");
  }
}
```



## Spring-Security 所有filter顺序列表

- ChannelProcessingFilter
- ConcurrentSessionFilter
- WebAsyncManagerIntegrationFilter
- SecurityContextPersistenceFilter
- HeaderWriterFilter
- CorsFilter
- CsrfFilter
- LogoutFilter
- OAuth2AuthorizationRequestRedirectFilter
- Saml2WebSsoAuthenticationRequestFilter
- X509AuthenticationFilter
- AbstractPreAuthenticatedProcessingFilter
- CasAuthenticationFilter
- OAuth2LoginAuthenticationFilter
- Saml2WebSsoAuthenticationFilter
- `UsernamePasswordAuthenticationFilter`
- ConcurrentSessionFilter
- OpenIDAuthenticationFilter
- DefaultLoginPageGeneratingFilter
- DefaultLogoutPageGeneratingFilter
- `DigestAuthenticationFilter`
- BearerTokenAuthenticationFilter
- `BasicAuthenticationFilter`
- RequestCacheAwareFilter
- SecurityContextHolderAwareRequestFilter
- JaasApiIntegrationFilter
- RememberMeAuthenticationFilter
- AnonymousAuthenticationFilter
- OAuth2AuthorizationCodeGrantFilter
- SessionManagementFilter
- `ExceptionTranslationFilter`
- `FilterSecurityInterceptor`
- SwitchUserFilter



## **Spring-Security支持的所有的 Authentication Mechanisms**

- Username and Password - how to authenticate with a username/password
- OAuth 2.0 Login- OAuth 2.0 Log In with OpenID Connect and non-standard OAuth 2.0 Login (i.e. GitHub)
- SAML 2.0 Login - SAML 2.0 Log In
- Central Authentication Server (CAS) - Central Authentication Server (CAS) Support
- Remember Me - How to remember a user past session expiration
- JAAS Authentication- Authenticate with JAAS
- OpenID - OpenID Authentication (not to be confused with OpenID Connect)
- Pre-Authentication Scenarios - Authenticate with an external mechanism such as SiteMinder or Java EE security but still use Spring Security for authorization and protection against common exploits.
- X509 Authentication - X509 Authentication



## 参考文档

[SpringSecurity官网](https://docs.spring.io/spring-security/site/docs/5.3.1.RELEASE/reference/html5/)