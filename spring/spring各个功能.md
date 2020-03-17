**org.springframework.context.annotation.PropertySource**

**org.springframework.context.support.PropertySourcesPlaceholderConfigurer**

用于解决placeholder，需要注册 PropertySourcesPlaceholderConfigurer

```xml
<!--等于自动注册了PropertySourcesPlaceholderConfigurer**-->
<context:property-placeholder>
```



**org.springframework.beans.factory.config.PropertyPlaceholderConfigurer**

spring3.1之前的

在没有spring-context模块（就是说不使用applicationContext的时候）用



**org.springframework.core.env.PropertySource**

**org.springframework.core.env.PropertyResolver**