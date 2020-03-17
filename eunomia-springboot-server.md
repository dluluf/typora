context-param:

``` java
    public InitParameterConfiguringServletContextInitializer initParamsInitializer() {
        Map<String, String> contextParams = new HashMap<>();
        contextParams.put("org.apache.myfaces.AUTO_SCROLL", "true");
        return new InitParameterConfiguringServletContextInitializer(contextParams);
    }

```





//@import DefaultApplication类

扫描com.pt.poseidon包，包括自定义注解@Service

扫描com.pt.eunomia包



```
//@EnableAutoConfiguration
@EnableDiscoveryClient
@EnableFeignClients(basePackages = {"${feign.client.scan.package:com.pt}"})
```

