## Method Security

### 如何使用

```java
@EnableGlobalMethodSecurity(jsr250Enabled = true)
@Configuration
public class EunomiaSecurityConfig extends GlobalMethodSecurityConfiguration {
}
```



注意这里需要添加注解 <font color = "red" > `@EnableGlobalMethodSecurity`  </font>

如果需要拓展 `GlobalMethodSecurityConfiguration`,则继承该类。否则，使用默认配置。



### 原理

注解<font color = "red" > `@EnableGlobalMethodSecurity` </font> 导入了 `GlobalMethodSecuritySelector.class`,这个类特别关键。

```java
@Import({ GlobalMethodSecuritySelector.class })
@EnableGlobalMethodSecurity
@Configuration
public @interface EnableGlobalMethodSecurity {
```

#### <font color="red" >`GlobalMethodSecuritySelector`</font>

```java
final class GlobalMethodSecuritySelector implements ImportSelector {

	public final String[] selectImports(AnnotationMetadata importingClassMetadata) {
		Class<EnableGlobalMethodSecurity> annoType = EnableGlobalMethodSecurity.class;
		Map<String, Object> annotationAttributes = importingClassMetadata
				.getAnnotationAttributes(annoType.getName(), false);
		AnnotationAttributes attributes = AnnotationAttributes
				.fromMap(annotationAttributes);
	
		Class<?> importingClass = ClassUtils
				.resolveClassName(importingClassMetadata.getClassName(),
						ClassUtils.getDefaultClassLoader());
		boolean skipMethodSecurityConfiguration = GlobalMethodSecurityConfiguration.class
				.isAssignableFrom(importingClass);

		AdviceMode mode = attributes.getEnum("mode");
		boolean isProxy = AdviceMode.PROXY == mode;
		String autoProxyClassName = isProxy ? AutoProxyRegistrar.class
				.getName() : GlobalMethodSecurityAspectJAutoProxyRegistrar.class
				.getName();

		boolean jsr250Enabled = attributes.getBoolean("jsr250Enabled");

		List<String> classNames = new ArrayList<String>(4);
		if(isProxy) {
			classNames.add(MethodSecurityMetadataSourceAdvisorRegistrar.class.getName());
		}

		classNames.add(autoProxyClassName);

		if (!skipMethodSecurityConfiguration) {
			classNames.add(GlobalMethodSecurityConfiguration.class.getName());
		}

		if (jsr250Enabled) {
			classNames.add(Jsr250MetadataSourceConfiguration.class.getName());
		}

		return classNames.toArray(new String[0]);
	}
}
```



> 这个类会根据用户的应用配置类和它添加的<font color = "red" > `@EnableGlobalMethodSecurity`  </font>注解的属性值，返回需要import的类名。

这里我们以之前的配置类：`EunomiaSecurityConfig`位例，此时该方法会添加的类有：

1. <font color = "red" > AutoProxyRegistrar</font>
2. <font color = "red" >`MethodSecurityMetadataSourceAdvisorRegistrar`</font>
3. `EunomiaSecurityConfig`
4. `Jsr250MetadataSourceConfiguration`

#### 非常关键一个类

<font color = "red" >`MethodSecurityMetadataSourceAdvisorRegistrar`</font>

```java
class MethodSecurityMetadataSourceAdvisorRegistrar implements
		ImportBeanDefinitionRegistrar {

	/**
	 * Register, escalate, and configure the AspectJ auto proxy creator based on the value
	 * of the @{@link EnableGlobalMethodSecurity#proxyTargetClass()} attribute on the
	 * importing {@code @Configuration} class.
	 */
	public void registerBeanDefinitions(AnnotationMetadata importingClassMetadata,
			BeanDefinitionRegistry registry) {

		BeanDefinitionBuilder advisor = BeanDefinitionBuilder
				.rootBeanDefinition(MethodSecurityMetadataSourceAdvisor.class);
		advisor.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
		advisor.addConstructorArgValue("methodSecurityInterceptor");
		advisor.addConstructorArgReference("methodSecurityMetadataSource");
		advisor.addConstructorArgValue("methodSecurityMetadataSource");

		MultiValueMap<String,Object> attributes = importingClassMetadata.getAllAnnotationAttributes(EnableGlobalMethodSecurity.class.getName());
		Integer order = (Integer) attributes.getFirst("order");
		if(order != null) {
			advisor.addPropertyValue("order", order);
		}

		registry.registerBeanDefinition("metaDataSourceAdvisor",
				advisor.getBeanDefinition());
	}
}
```

这里会手动注册一个Advisor: `MethodSecurityMetadataSourceAdvisor`

`MethodSecurityMetadataSourceAdvisor`的 beanName指向的就是`GlobalMethodSecurityConfiguration#methodSecurityInterceptor`

即最后使用了`methodSecurityInterceptor`这个bean。





### 疑问

到这里你可能会想问那`ImportSelector#selectImports`什么时候被调用？

具体请参考 [`ImportSelector`]()