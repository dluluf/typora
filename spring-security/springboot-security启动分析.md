### 前言

spring-security是基于Servlet的，也就是基于Filter。

- 只要添加了Filter，在web应用请求这个filter就会被应用。

- 需要注意Filter的顺序。

  

### Springboot中配置的Spring-Security 的Filter

spring-security应用前提：需要配置一个Filter

在 `springboot + spring-security`中通过 `@EnableWebSecurity`注解引入`WebSecurityConfiguration`，

其中定义了`springSecurityFilterChain`这个`Bean`。需要注意的是这里`bean`的创建是通过`build`模式创建的。

其中`WebSecurity`是`SecurityBuilder`的实现类。

```java
@Bean(name = AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
public Filter springSecurityFilterChain() throws Exception {
    boolean hasConfigurers = webSecurityConfigurers != null
        && !webSecurityConfigurers.isEmpty();
    if (!hasConfigurers) {
        WebSecurityConfigurerAdapter adapter = objectObjectPostProcessor
            .postProcess(new WebSecurityConfigurerAdapter() {
            });
        webSecurity.apply(adapter);
    }
    return webSecurity.build();
}
```



### 如何一步步到最终添加这个关键的 `springSecurityFilterChain`

`SecurityAutoConfiguration`

```java
@Configuration
@ConditionalOnClass({ AuthenticationManager.class,
		GlobalAuthenticationConfigurerAdapter.class })
@EnableConfigurationProperties
@Import({ SpringBootWebSecurityConfiguration.class,
		AuthenticationManagerConfiguration.class,
		BootGlobalAuthenticationConfiguration.class, SecurityDataConfiguration.class })
public class SecurityAutoConfiguration {
```



这里导入了springboot为我们默认添加的安全配置类：`SpringBootWebSecurityConfiguration`，当我们没有创建`WebSecurityConfiguration.class`的bean时，该配置类才会被加载。

```java
@Configuration
@EnableConfigurationProperties
@ConditionalOnClass({ EnableWebSecurity.class, AuthenticationEntryPoint.class })
@ConditionalOnMissingBean(WebSecurityConfiguration.class)
@ConditionalOnWebApplication
@EnableWebSecurity
public class SpringBootWebSecurityConfiguration {
```

这个类中添加了`@EnableWebSecurity`

```java
@Retention(value = java.lang.annotation.RetentionPolicy.RUNTIME)
@Target(value = { java.lang.annotation.ElementType.TYPE })
@Documented
@Import({ WebSecurityConfiguration.class,
		SpringWebMvcImportSelector.class })
@EnableGlobalAuthentication
@Configuration
public @interface EnableWebSecurity {

```

`EnableWebSecurity`中导入了`WebSecurityConfiguration.class` ,其中会定义一个bean

```java
	/**
	 * Creates the Spring Security Filter Chain
	 * @return
	 * @throws Exception
	 */
	@Bean(name = AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
	public Filter springSecurityFilterChain() throws Exception {
		boolean hasConfigurers = webSecurityConfigurers != null
				&& !webSecurityConfigurers.isEmpty();
		if (!hasConfigurers) {
			WebSecurityConfigurerAdapter adapter = objectObjectPostProcessor
					.postProcess(new WebSecurityConfigurerAdapter() {
					});
			webSecurity.apply(adapter);
		}
		return webSecurity.build();
	}
```
这里先判断是否有`webSecurityConfigures`的配置，这里在类中通过set方法注入了该配置。
```java
	@Autowired(required = false)
	public void setFilterChainProxySecurityConfigurer(
			ObjectPostProcessor<Object> objectPostProcessor,
			@Value("#{@autowiredWebSecurityConfigurersIgnoreParents.getWebSecurityConfigurers()}") List<SecurityConfigurer<Filter, WebSecurity>> webSecurityConfigurers)
			throws Exception {
		webSecurity = objectPostProcessor
				.postProcess(new WebSecurity(objectPostProcessor));
		if (debugEnabled != null) {
			webSecurity.debug(debugEnabled);
		}

		Collections.sort(webSecurityConfigurers, AnnotationAwareOrderComparator.INSTANCE);

		Integer previousOrder = null;
		Object previousConfig = null;
		for (SecurityConfigurer<Filter, WebSecurity> config : webSecurityConfigurers) {
			Integer order = AnnotationAwareOrderComparator.lookupOrder(config);
			if (previousOrder != null && previousOrder.equals(order)) {
				throw new IllegalStateException(
						"@Order on WebSecurityConfigurers must be unique. Order of "
								+ order + " was already used on " + previousConfig + ", so it cannot be used on "
								+ config + " too.");
			}
			previousOrder = order;
			previousConfig = config;
		}
		for (SecurityConfigurer<Filter, WebSecurity> webSecurityConfigurer : webSecurityConfigurers) {
			webSecurity.apply(webSecurityConfigurer);
		}
		this.webSecurityConfigurers = webSecurityConfigurers;
	}
```

> 到这里Filter已经创建完成。