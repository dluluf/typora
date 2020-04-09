# InstantiationAwareBeanPostProcessor

## 接口定义

```java
//实现这个接口的两个回调，可以在bean实例化之前和之后做一些操作
public interface InstantiationAwareBeanPostProcessor extends BeanPostProcessor {

   /**
    * 在实例化之前
    */
   Object postProcessBeforeInstantiation(Class<?> beanClass, String beanName) throws BeansException;

   /**
    * 这个操作，是在bean已经实例化，但是属性值没有被设置之前，autowire也没有被注入。
    */
   boolean postProcessAfterInstantiation(Object bean, String beanName) throws BeansException;

   /**
    * 这里可以对bean的属性进行一些操作，比如校验pds中需要加载的属性对象是否已经在容器中存在了，如 
    * required对象
    * 也可对该bean的属性进行设置，通过pvs来对bean的属性进行设置
    * 返回：就是我们设置的pvs,如果为空，则不设置bean属性。
    */
   PropertyValues postProcessPropertyValues(
         PropertyValues pvs, PropertyDescriptor[] pds, Object bean, String beanName) throws BeansException;

}
```

```java
org.springframework.beans.factory.config.BeanPostProcessor
```

这个接口是在初始化前后，做处理。



## 使用场景

对目标bean，不是按一般bean实例创建的方式来处理。

用户需要进行一些其他操作来替换或者修改bean的实例化过程。

例如：

1、对目标资源创建代理，比如数据连接池、懒加载的bean

2、对目标bean实现一个额外的注入策略。比如字段注入。



## 使用注意

这个类主要是spring 框架内部使用的，可能spring对他还有一些其他的拓展。

所以我们尽可能不要使用该接口。建议我们可以使用`BeanPostProcessor`接口

或者使用`InstantiationAwareBeanPostProcessorAdapter`。





## 案例
