#### cas接入

##### 1.spring-security-cas接入

​	基于spring-security框架的项目，比如我们的 **EUNOMIA**，通过spring-security-cas直接接入cas-server。因为这里spring-security对cas做了集成，本质和通过cas-client,使用filter来接入cas-server没有区别。只不过在使用spring-security框架后的项目上接入cas-server更快捷。

##### 2.cas-client接入

​	这种就是没有基于spring-security框架的web项目，直接通过使用cas-client，在web.xml通过filter配置来连接cas-server。