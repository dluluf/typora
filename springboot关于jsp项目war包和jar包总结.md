-----------------------------------------------------------------------------

`org.apache.jasper.JasperException `  解决

```java
<dependency>  
	<groupId>javax.servlet</groupId>  
	<artifactId>jstl</artifactId>
</dependency>
```

jstl 1.1和1.2版本在tomcat 8中的不同，在内嵌的tomcat8 容器中需要添加该jar包。否则，抛异常`org.apache.jasper.JasperException`

```java
JSTL1.0的使用方法为：
<%@ taglib uri="http://java.sun.com/jstl/core" prefix="c" %>
 
JSTL1.1的使用方法为：
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
 
JSTL1.2的使用方法为
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>

```

----------------------------------------

tomcat中包含的jar包有：

`jsp-api`

`servlet-api`









jsp项目开发

标准方式：webapp

jar包：需要在build的时候将webapp中的文件打包到META-INF/resource目录中

war包：则不需要





jar包依赖的添加：







war包依赖的添加：

server.servlet.jsp.init-parameters.development=true

```java
<!-- servlet 依赖包 -->
<dependency>
    <groupId>javax.servlet</groupId>
    <artifactId>javax.servlet-api</artifactId>
   <!-- <scope>provided</scope>-->
</dependency>

<!--配置jsp jstl的支持-->
<dependency>
    <groupId>javax.servlet</groupId>
    <artifactId>jstl</artifactId>
</dependency>
<!--对jsp的支持-->
<dependency>
    <groupId>org.apache.tomcat.embed</groupId>
    <artifactId>tomcat-embed-jasper</artifactId>
    <scope>provided</scope>
</dependency>
<!-- 热部署 -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-devtools</artifactId>
    <optional>true</optional>
</dependency>
<!--Provided  start-->
<!--War包部署到外部的Tomcat中已经包含了这些，所以需要添加以下依赖 否则会和内嵌的Tomcat 容器发生冲突 -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-tomcat</artifactId>
    <scope>provided</scope>
</dependency>
```

application.yml

```java
#如果按照一般web工程将页面放在src/main/webapp/WEB-INF/jsp/，则配置前缀
spring.mvc.view.prefix=/WEB-INF/jsp
spring.mvc.view.suffix=.jsp
# 配置Tomcat编码
server.tomcat.uri-encoding=UTF-8
server.port=8001
server.servlet.context-path=/boot
```

### 总结：

> **springboot 2.2.4**
>
> #### jar:
>
> - jar包在idea中可以访问webapp中的资源。但是打包后通过java -jar 启动应用，不能访问webapp中的资源，不管你是否在build中添加webapp到META-INF/resources中。
> - 在idea中启动，静态资源优先访问的是webapp中的
>
> ####  war:
>
> - 必须有webapp目录
> - springboot2.2.4 直接打war,可以访问在webapp中jsp页面。
> - 在idea中启动，静态资源优先访问的是static中的



1.webapp是在打war包时，war的插件会打包；在打jar包时，会被忽略

2.idea中可能添加了web的配置，会把webapp中的资源添加到了项目中

+ 这里可以去测试几种情况

  这里需要测试两种启方式：idea的启动 和 java -jar 方式

  + 1.jar包，idea不配置web,看是否能访问webapp中的资源;同时使用java -jar 方式启动查看是否能 -- 应该是不能
  + 2.jar包，idea中配置web，通过idea和java -jar两种方式启动
  + 3.war包，重复上面的过程
  + 

### 问题

为什么不能再template中添加这个jsp页面？



#### 为什么jsp需要webapp目录？

`org.springframework.boot.web.servlet.server.DocumentRoot`

`private static final String[] COMMON_DOC_ROOTS = { "src/main/webapp", "public", "static" }`

pulic 和 static 已经用来存放静态资源了，tomcat只会从这里面获取资源，所以jsp只能放在webapp下了。

> 这个解释应该是不准确，但是基本上跟内嵌的tomcat 读取资源，或者配置的对jsp的支持有关系。
>
> 后续发现：这里有一个加载顺序，首先是"src/main/webapp"，如果有这个目录，直接从这里去资源文件，直接返回了。而且这里pulic 和static 都被校验成不是一个目录（只有相对于项目的根目录下的比如src/main/resources/public才是一个目录），这里都不能存放jsp资源。

tomcat作为ServletWebServer 的源码：`TomcatServletWebServerFactory `







找不到页面：

```java
@Configuration
public class TomcatConfig {
    @Value("${bw.factory.doc.root}")
    private String rootDoc;
    @Bean
    public AbstractServletWebServerFactory embeddedServletContainerFactory() {
       
        TomcatServletWebServerFactory tomcatServletWebServerFactory = new TomcatServletWebServerFactory();
        tomcatServletWebServerFactory.setDocumentRoot(
                new File(rootDoc));
        return  tomcatServletWebServerFactory;
    }
}
属性文件配置：

bw.factory.doc.root=bw.factory.doc.root=D:/project/smallfile/all/all_consumer/src/main/webapp

```

```xml
<build>
   <!--指定mapper存放路径-->
        <resources>
            <resource>
                <directory>src/main/java</directory>
                <includes>
                    <include>**/*.xml</include>
                </includes>
            </resource>
            <!--引用JS/CSS/JSP页面位置-->
            <resource>
                <directory>src/main/webapp</directory>
                <includes>
                    <include>**/*.*</include>
                </includes>
            </resource>
            <!--指定配置文件存放路径-->
            <resource>
                <directory>src/main/resources</directory>
                <includes>
                    <include>**/*.*</include>
                </includes>
                <filtering>false</filtering>
            </resource>

        </resources>
    <plugins>
        <plugin>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-maven-plugin</artifactId>
            <version>1.4.2.RELEASE</version>
        </plugin>
    </plugins>
</build>
```



