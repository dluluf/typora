









spring/springboot 事件机制

Observeable

Observer

EventObject

EventListerner



ApplicationEvent

ApplicationListener



SpringBoot

​	ApplicationEnviromentPreparedEvent



configFileApplicationListener



BootstrapApplicationListener



java spi:`serviceLoader`

-------------



























《j2ee design patterns》

《servlet-3.1_final》



serveletContextListenner->contextLoaderListerner->ROOt webappllicationcONTEXT

​											->dispatcherServlet-> servlet webapplicationcontext





## config

java api config

apache commons config 

spring cloud config

nacos config

​	订阅服务

## 服务注册发现

zk

​	目录方式，根据seviceId，你需要什么service，返回什么。

eureka

​	实例过多不好用

​	返回所有的实例。

consul

​	

《从paxos到zk》



springcloud 服务发现 定时去注册中心 更新，如果实例过多，造成缓存过大。



discoveryClient接口

