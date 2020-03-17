

### 一个很重要的点：

一般框架或者插件，有一个默认的处理类。但这个实例不直接处理业务逻辑，而是交给这个实例中管理的某个对象去处理。这是设计模式的体现。



比如在spring-security中，`ProviderManager` 是安全管理的入口，但是`ProviderManager`中不直接处理（当然这里也可以直接去执行认证操作，但是一般不这样处理），而是由它管理的 **`AuthenticationProvider` 's** 去处理具体的逻辑。而这里`AuthenticationProvider`是一个接口，需要提供具体的实现。



### 从 authentication 和 authorization 开始

spring-security中的authentication 和authorization

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

源码：

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

`ProviderManager`管理了一个父的`AuthenticationManager`，作为最后的兜底。就是说当所有的认证机制都无法判断的时候，即返回为空的时候，此时可以通过父类来处理。如果没有定义这个父类，是会抛出
AuthenticationException。





#### Authorization ：

AccessDecisionManager

AccessDecisionVoter：
```java

boolean supports(ConfigAttribute attribute);

boolean supports(Class<?> clazz);

int vote(Authentication authentication, S object,
        Collection<ConfigAttribute> attributes);
```


ConfigAttributes:


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



这个是在默认的链上添加新的链
```java

@Configuration
@Order(SecurityProperties.BASIC_AUTH_ORDER - 10)
public class ApplicationConfigurerAdapter extends WebSecurityConfigurerAdapter {
  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.antMatcher("/foo/**")
     ...;
  }}
```






如果嵌入到web应用中，就是通过filter来实现

spring-security如何应用，其原理也是通过filter.

接下来就看一下这个filter。



filter顺序的控制，两种方式
1.@Order或者实现 Order接口
2.通过FilterResigstrationBean的api设置



springboot应用中默认注入了@Bean
FilterChainProxy

这个类中可以管理很多的filters来实现很多功能。


整体自上而下的过程：
![0c63cd2617c6907c1b30ef37802886cd.png](en-resource://database/410:1)

![3f60f83afd640295241ce31d230f60e8.png](en-resource://database/412:1)


![95561c170de539398957b14db5d3318a.png](en-resource://database/414:1)



![19992a59bb9ffbc0b14ed45613139986.png](en-resource://database/416:1)


方法级别的安全处理：

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
当方法被注解后，创建bean的时候会生成一个代理类，则当被调用时，会经过安全检查相关的拦截器的处理。当被拦截是，则返回
AccessDeniedException 。


@PreAuthorize and @PostAuthorize

这两个注解，可以使用表达式语言动态获取是否通过安全检查。





```java
SecurityConfigurerAdapter
```



### spring-security 


#### Web Security 的原理
> web安全是通过filter来实现的，spring-security也是基于 Servlet Filters 来实现的。spring-security框架是一个filter，这个filter添加进了web filter chain 中。

![](C:\Users\Administrator\Pictures\aspeed_spring_security\security-filters.png)



spring boot应用中，如果对一个request 添加过滤器，一般实现  `OrderedFilter` 接口,然后定义Filter的order,这个值是一个小于0的值。

```java
public interface OrderedFilter extends Filter, Ordered {   
    /** 
    * Filters that wrap the servlet request should be ordered less than or equal to this.  
    */  
    int REQUEST_WRAPPER_FILTER_MAX_ORDER = 0;
}
```



DelegatingFilterProxy （Spring-Web） ->FilterChainProxy (Spring-Security)->

这里看出Spring是通过DelegatingFilterProxy来整合Spring-Security的
>这个类在我们的web.xml配置中使用的，当我们定义的filter为DelegatingFilterProxy，此时呢，所有的请求filter,都会去容器中找一个叫springsecurityfilterchain的bean来处理。这里是方便我们去处理web应用，当我们需要一个filter来处理，此时我们只需要在spring相关的配置文件中定义一个bean,id为`springSecurityFilterChain` ，而在web.xml中写成DelegatingFilterProxy。

DelegatingFilterProxy:不需要是一个spring 的bean,也就是说在不使用spring容器开发的应用中，可以是有该类。或者说在spring容器还没有初始化的时候，可以使用该类来处理。

DelegatingFilterProxy 把处理的执行交给了 FilterChainProxy（注意这个类是spring-security中的类，然后会有很多这样的类去做具体的filter操作），这个bean一般使用 `springSecurityFilterChain` 这个bean id来做配置。

>FilterChainProxy这里代理中包含很多的filter(关于spring-security安全认证和权限控制的filters),当然也可以是不同的filter chains,不过一个请求只会被一个filter chain处理，一般是根据请求路径来判断交给那个filter chain处理。
>这里就是我们需要关注和定义的filters。

![95561c170de539398957b14db5d3318a.png](en-resource://database/396:1)



一般springboot应用中有6条filter chains,前5个是用来控制静态文件和错误页面的（可以通过配置security.ignored来定义资源路径）。最后一个filter chain 默认会对 `/**` 进行控制（包括认证、授权、异常处理、session处理、请求头处理等等）。默认最后一个chain有11个filters,不过一般我们不需要太关注这些filters。


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

>**注意**：
>如果想在spring-security 的chain中添加filter，不要通过使用@bean 或者 FilterRegistrationBean 方式去添加，这两种方式都会将filter应用于整个web 的filter chains中，而不是spring-security 的chain中。应该通过继承 WebSecurityConfigurerAdapter 这种方式添加新的chain。







| Alias          | Filter Class            | Namespace Element or Attribute      |
| -------------- | ----------------------- | ----------------------------------- |
| CHANNEL_FILTER | ChannelProcessingFilter | http/intercept-url@requires-channel |
|SECURITY_CONTEXT_FILTER | SecurityContextPersistenceFilter|http 
|CONCURRENT_SESSION_FILTER | ConcurrentSessionFilter|session-management/concurrency-control |
|HEADERS_FILTER |HeaderWriterFilter |http/headers |
|CSRF_FILTER |CsrfFilter |http/csrf |
|LOGOUT_FILTER |LogoutFilter | http/logout|
|X509_FILTER |X509AuthenticationFilter| http/x509  |
|PRE_AUTH_FILTER |AbstractPreAuthenticatedProcessingFilter  |N/A |
|CAS_FILTER |CasAuthenticationFilter |N/A  |
|FORM_LOGIN_FILTER | UsernamePasswordAuthenticationFilter|http/form-login  |
|BASIC_AUTH_FILTER |BasicAuthenticationFilter |http/http-basic |
|SERVLET_API_SUPPORT_FILTER |SecurityContextHolderAwareRequestFilter |http/@servlet-api-provision|
|JAAS_API_SUPPORT_FILTER |JaasApiIntegrationFilter |http/@jaas-api-provision|
|REMEMBER_ME_FILTER |RememberMeAuthenticationFilter |http/remember-me |


配置自定义的安全管理
通过继承
WebSecurityConfigurerAdapter 
添加新的过滤器链来处理。

spring-security安全处理链需要一个匹配的路径，一个请求只会匹配一个路径，一旦匹配某个处理链，其他的链就不会再处理。不过，如果需要细化的话，可以通过在HttpSecurity中配置更细化的路径。
```java

@Configuration@Order(SecurityProperties.BASIC_AUTH_ORDER - 10)public class ApplicationConfigurerAdapter extends WebSecurityConfigurerAdapter {
  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.antMatcher("/foo/**")
      .authorizeRequests()
        .antMatchers("/foo/bar").hasRole("BAR")
        .antMatchers("/foo/spam").hasRole("SPAM")
        .anyRequest().isAuthenticated();
  }}
```





```java

public interface AuthenticationManager {

  Authentication authenticate(Authentication authentication)
    throws AuthenticationException;

}
```
认证处理器，
返回值有三种情况：
如果返回认证异常，我们可以捕获后跳转到认证页面，比如登入页面，或者返回认证错误页面，在接口调用时，可以返回401响应等等



ProviderManager
实现类，但是不直接处理，而是将具体的认证处理委托给实现
AuthenticationProvider 接口的实例。
这里ProviderManager可以管理多个AuthenticationProviders.
当遇到不支持的认证类型，直接跳过不去处理。

```java

public interface AuthenticationProvider {

        Authentication authenticate(Authentication authentication)
                        throws AuthenticationException;

        boolean supports(Class<?> authentication);

}
```

这里与AuthenticationManager接口差不多，但是多了一个接口supports,可以通过这个接口指定支持认证的类型，也就是说可以通过实现这个接口，排除一些我们不需要去进行认证的一些认证类型。

比如我们通过某个过滤器 做了认证处理后，返回的认证结果，他的结果类型是不一样的，在下一个过滤器做处理的时候，我们可以根据这个类型，判断是否继续处理。

ProviderManager可以有一个父的 AuthenticationProvider实现，当所有的子provider都返回空的时候，就会看这个父类怎么处理，如果没有，则抛出认证异常。


![19992a59bb9ffbc0b14ed45613139986.png](en-resource://database/404:1)



这里每个providerManager都可以对某一个特定的资源做安全处理，比如路径/admin/* 或者 /account/* ,然后可以有一个父的来处理/* 或者说是一个兜底的处理，可以返回一个友好的处理，比如返回一个认证处理失败页面。








```java

@Configurationpublic class ApplicationSecurity extends WebSecurityConfigurerAdapter {

   ... // web stuff here

  @Autowired
  public void initialize(AuthenticationManagerBuilder builder, DataSource dataSource) {
    builder.jdbcAuthentication().dataSource(dataSource).withUser("dave")
      .password("secret").roles("USER");
  }

}
```
这是在spingboot中去配置一个全局的 authenticationManger