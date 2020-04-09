

#### csrfFilter

**跨站请求伪造**（英语：Cross-site request forgery）







---------------------------------

# spring-security 模块改造

### 注意

>Poseidon底层框架中对springBoot的自动配置，排除了很多。
>
>现在的项目，其实可以说是重复造轮子。
>
>个人认为应该在底层框架兼容而不是排除SpringBoot的配置。
>
>改造需要第一个改造的应该就是poseidon-cloud-support项目
>
>



```java
securityFilterChainBuilders
```

这里我们会添加很多的securityFilterChains,比如oauth2的，不受保护的，其他的。





对于某一个securityFilterChain，其中很可能添加很多的filter.这里如何添加，

可以自定义一个类型，我们获取该类型的所有filter,通过order注解，顺序的将filter应用到http中。