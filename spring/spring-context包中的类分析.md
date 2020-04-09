####   `org.springframework.context.ApplicationContextInitializer`

在spring的`ConfigurableApplicationContext#refresh()`调用前的一个回调接口

使用场景：当我们需要去定义（改变或者修改）应用上下文的初始化。

比如：在初始化之前添加配置资源（配置外置）、激活特定的profiles



在web.xml如何使用：

```java
ContextLoader：
<context-param>
		<param-name>contextInitializerClasses</param-name>
		<param-value>ApplicationContextInitializer.class 实现类</param-value> 
</context-param>
            
FrameworkServlet(定义的servlet)
<init-param>
  <param-name>contextInitializerClasses</param-name>
  <param-value>ApplicationContextInitializer.class 实现类</param-value>
</init-param>                      
```



