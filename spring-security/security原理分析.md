



## Spring-Security 

[https://spring.io/guides/topicals/spring-security-architecture/](https://spring.io/guides/topicals/spring-security-architecture/) 



### 一个很重要的点：

一般框架或者插件，有一个默认的处理类。但这个实例不直接处理业务逻辑，而是交给这个实例中管理的某个对象去处理。这是设计模式的体现。

比如在spring-security中，`ProviderManager` 是安全管理的入口，但是`ProviderManager`中不直接处理（当然这里也可以直接去执行认证操作，但是一般不这样处理），而是由它管理的 **`AuthenticationProvider` 's** 去处理具体的逻辑。而这里`AuthenticationProvider`是一个接口，需要提供具体的实现。

### 调用过程分析

org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter#attemptAuthentication

org.springframework.security.authentication.AuthenticationManager#authenticate

`attemptAuthentication` 的实现就是对认证信息的封装，封装成  <font color="red"> `Authentication `</font> 对象

- 比如 `org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter`

```java

/**
 * UsernamePasswordAuthenticationFilter
 * 这里就是将 username password 封装了
 */
public Authentication attemptAuthentication(HttpServletRequest request,
			HttpServletResponse response) throws AuthenticationException {
		if (postOnly && !request.getMethod().equals("POST")) {
			throw new AuthenticationServiceException(
					"Authentication method not supported: " + request.getMethod());
		}
		String username = obtainUsername(request);
		String password = obtainPassword(request);
		if (username == null) {
			username = "";
		}
		if (password == null) {
			password = "";
		}
		username = username.trim();
		UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);

		// Allow subclasses to set the "details" property
		setDetails(request, authRequest);
		return this.getAuthenticationManager().authenticate(authRequest);
	}
```



### 从 authentication 和 authorization 开始



#### Authentication：
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
//
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

        Authentication authenticate(Authentication authentication)
                        throws AuthenticationException;
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
				prepareException(e, authentication);
				// SEC-546: Avoid polling additional providers if auth failure is due to
				// invalid account status
				throw e;
			}
			catch (InternalAuthenticationServiceException e) {
				prepareException(e, authentication);
				throw e;
			}
			catch (AuthenticationException e) {
				lastException = e;
			}
		}
		if (result == null && parent != null) {
			// Allow the parent to try.
			try {
				result = parent.authenticate(authentication);
			}
			catch (ProviderNotFoundException e) {
				// ignore as we will throw below if no other exception occurred prior to
				// calling parent and the parent
				// may throw ProviderNotFound even though a provider in the child already
				// handled the request
			}
			catch (AuthenticationException e) {
				lastException = e;
			}
		}
		if (result != null) {
			if (eraseCredentialsAfterAuthentication
					&& (result instanceof CredentialsContainer)) {
				// Authentication is complete. Remove credentials and other secret data
				// from authentication
				((CredentialsContainer) result).eraseCredentials();
			}

			eventPublisher.publishAuthenticationSuccess(result);
			return result;
		}
		// Parent was null, or didn't authenticate (or throw an exception).
		if (lastException == null) {
			lastException = new ProviderNotFoundException(messages.getMessage(
					"ProviderManager.providerNotFound",
					new Object[] { toTest.getName() },
					"No AuthenticationProvider found for {0}"));
		}
		prepareException(lastException, authentication);
		throw lastException;
	}
```



##### 同时提供多种认证机制

- 如何提供多种认证机制的？

  就是通过这里的AuthenticationProvider，因为`ProviderManager`他管理了多个`AuthenticationProvider`，每一种机制可以是一个`AuthenticationProvider`的实现。

- 是否需要考虑各个认证机制的顺序？

  不需要考虑各个机制的顺序问题，因为只要一个认证通过就ok了。（代码实现是直接跳出循环）

##### Parent AuthenticationManager

> `ProviderManager`管理了一个父的`AuthenticationManager`，作为最后的兜底。就是说当所有的认证机制都无法判断的时候，即返回为空的时候，此时可以通过父类来处理。如果没有定义这个父类，是会抛出
> AuthenticationException。



>Sometimes an application has logical groups of protected resources (e.g. all web resources that match a path pattern `/api/**`), and each group can have its own dedicated `AuthenticationManager`. Often, each of those is a `ProviderManager`, and they share a parent. The parent is then a kind of "global" resource, acting as a fallback for all providers.

<img src="C:\Users\Administrator\Pictures\aspeed_spring_security\authentication.png" style="zoom:50%;" />

##### 总结

这里的意思就是，比如

api/resources1,api/resources2,api/resources3

这里都matche  api/**,但是对于resources1 、 resources2、都有不同的认证处理，但是他们可以共用同一个parent ProviderManager。

这里对每个resources的处理，其实也是细化了处理过程。最初的执行链还是api/** match的那一条链，只不过在这个链下又多了更多细化的处理。



##### 认证处理的结果

三种情况：

- 成功
- 不能决定
- 异常

如果返回认证异常，我们可以捕获后跳转到认证页面，比如登入页面，或者返回认证错误页面，在接口调用时，可以返回401响应等等





#### Authorization ：



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

```java

public interface AccessDecisionManager {
	void decide(Authentication authentication, Object object,
			Collection<ConfigAttribute> configAttributes) throws AccessDeniedException,
			InsufficientAuthenticationException;
	boolean supports(ConfigAttribute attribute);
	boolean supports(Class<?> clazz);
}
```

AccessDecisionVoter：

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



#### springboot中AccessDecisionManager的创建过程

>AbstractInterceptUrlConfigurercreate->
>
>FilterSecurityInterceptor ->
>
>getAccessDecisionManager ->
>
>AffirmativeBased



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





#### ConfigAttributes:

对象S就是我们需要授权的对象，比如对一个方法的授权或者对一个url的授权。
这里ConfigAttributes是对授权对象做了一个包装，也就是说授权对象实现了该类，然后我们可以根据在里面添加的属性值，来判断该对象拥有什么级别的权限。比如eunomia中的所有权限、无权限等等。

AccessDecisionManager默认的实现类有AffirmativeBased，返回1表示授权成功。 通常使用这个类处理，但是我们也可以在AccessDecisionVoter的实现类中来处理是否授权成功。

常用的SpEl表达式方式 `isFullyAuthenticated() && hasRole('FOO') `
如果需要拓展其他的表达式，则需要通过实现
SecurityExpressionRoot 和
SecurityExpressionHandler。




spring-security框架提供的安全认证及授权

默认有6条链，前5条链是用来处理静态资源的，比如css、images、/error等等

最后一条链处理/** ， 我们主要的处理逻辑都在这里。
默认的处理chain:ApplicationWebSecurityConfigurerAdapter





### 方法级别的安全处理：

```java

@SpringBootApplication
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SampleSecureApplication {}
```


```java

@Servicepublic class MyService {

  @Secured("ROLE_USER")//根据 ConfigAttribute 中申明的类型来判断。
  public String secure() {
    return "Hello Security";
  }

}
```
当方法被注解后，创建bean的时候会生成一个代理类，则当被调用时，会经过安全检查相关的拦截器的处理。当被拦截是，则返回 `AccessDeniedException` 。

#### @PreAuthorize 

####  @PostAuthorize

这两个注解，可以使用表达式语言动态获取是否通过安全检查。





### 从Servlet容器到Spring-Security

#### 入口

> web安全是通过filter来实现的，spring-security也是基于 Servlet Filters 来实现的。spring-security框架是一个filter，这个filter添加进了web filter chain 中。

<img src="C:\Users\Administrator\Pictures\aspeed_spring_security\security-filters.png" style="zoom:50%;" />



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



<img src="C:\Users\Administrator\Pictures\aspeed_spring_security\security-filters-dispatch.png" style="zoom:50%;" />



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
>
>当然这里还有其他的filter  chain ，个数好像是6个。






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



#### **Standard Filter Aliases and Ordering**

org.springframework.security.config.annotation.web.builders.FilterComparator





#### Springboot中自定义Web 容器filter顺序的控制

1.@Order或者实现 Order接口
2.通过FilterResigstrationBean的api设置



#### SpringSecurity中自定义Filter顺序控制



spring boot应用中，如果对一个request 添加过滤器，一般实现  `OrderedFilter` 接口,然后定义Filter的order,这个值是一个小于0的值。

```java
public interface OrderedFilter extends Filter, Ordered {   
    /** 
    * Filters that wrap the servlet request should be ordered less than or equal to this.  
    */  
    int REQUEST_WRAPPER_FILTER_MAX_ORDER = 0;
}
```





### authenticationManager 认证接口的调用

从哪里，什么时候开始调用的？

### SpringSecurity在SpringBoot中应用：

#### 如何添加一个新链

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

#### 如何覆盖默认配置

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



#### 配置全局共享对象


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


### security-cas

filter进来

requestMatcher

privoderManager

authenticationProvider

- [ ] jdbc\security-cas

认证信息保存 tokenRepositery

认证页面


