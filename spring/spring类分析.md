```java
public interface ImportSelector {

   /**
    * Select and return the names of which class(es) should be imported based on
    * the {@link AnnotationMetadata} of the importing @{@link Configuration} class.
    */
   String[] selectImports(AnnotationMetadata importingClassMetadata);

}
```

这个类经常在spring-boot中使用，目的是用来动态的导入一些配置类。

例如：

```java
@EnableGlobalMethodSecurity
@Configuration
MyConfiguration {}
```

当我们自定义的 `MyConfiguration`添加了<font color="red" >`@EnableGlobalMethodSecurity` </font>,则会根据 `@Import({ GlobalMethodSecuritySelector.class })` 这个类中对接口`ImportSelector` 的实现，来动态的添加配置类。



```java
@Retention(value = java.lang.annotation.RetentionPolicy.RUNTIME)
@Target(value = { java.lang.annotation.ElementType.TYPE })
@Documented
@Import({ GlobalMethodSecuritySelector.class })
@EnableGlobalAuthentication
@Configuration
public @interface EnableGlobalMethodSecurity {
```

`GlobalMethodSecuritySelector` 的实现如下：

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



## 何处调用该接口呢？

spring-context

`ConfigurationClassPostProcessor` -> `ConfigurationClassParser`



org.springframework.context.annotation.ConfigurationClassPostProcessor

​	-> org.springframework.context.annotation.ConfigurationClassPostProcessor#postProcessBeanDefinitionRegistry

​	->org.springframework.context.annotation.ConfigurationClassPostProcessor#postProcessBeanFactory



org.springframework.context.annotation.ConfigurationClassParser

-> 