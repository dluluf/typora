### spring这些接口设计的思考

具体源码的设计

这些接口在调用过程的哪一个部分

----------------------------------
**org.springframework.beans.factory.InitializingBean**

容许在bean的所有属性字段加载完成后，用户自定义该bean的初始化或者当一些bean需要强制性bean校验的时候，也可以用。

> 也就是说：当我们需要自定义bean的初始化或者做属性的强制性校验可以实现这个接口。	
--------------------------------------

### 后置处理器

BeanPostProcessor：
	可以在bean被返回之前做一些处理，
	可以在bean初始化返回后做一些处理（如果是工厂bean,会被调用两次）
postProcessBeanFactory（）：
	钩子方法，可以在这里修改spirng 内部的bean工厂。

--------------------------------

**org.springframework.beans.factory.config.BeanFactoryPostProcessor**

```java
public interface BeanFactoryPostProcessor {

	/**
	 * Modify the application context's internal bean factory after its standard
	 * initialization. All bean definitions will have been loaded, but no beans
	 * will have been instantiated yet. This allows for overriding or adding
	 * properties even to eager-initializing beans.
	 * @param beanFactory the bean factory used by the application context
	 * @throws org.springframework.beans.BeansException in case of errors
	 */
	void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException;

}
```

>这个后置处理器，让我们在spring的标准bean初始化之后（但是没有实例化），提供了一个入口，实现这个接口，可以修改或者添加内部所有bean的属性。

--------------------


**org.springframework.beans.factory.config.AutowireCapableBeanFactory**

最重要的作用：可以通过注入该实例工厂，用该工厂将外部框架的bean交给spring容器。

>这个类可以用来注入外部的bean,或者说如果只知道类class或者名称，就可以注入该bean,不需要bean的定义。
>与beanFactoryPostProcessor修改bean的定义不同，这里也是需要现有的bean的定义。而AutowireCapableBeanFactory 不需要bean的定义就可以创建。
>这个bean好像是一个prototype类型的。


>**也可以对已经存在的bean的实例，做初始化。这里应该是将普通的bean实例（不是spring bean），在spring容器中创建一个新的bean的实例。**



org.springframework.beans.factory.config.AutowireCapableBeanFactory

一个可以被自动注入的bean,也就是说已经可以被spring管理的的工厂，来实现这个接口。目的是给自定义框架中的bean实例提供方法调用。也就是说，其他框架中的bean也可以调用这个接口中的方法了。



可以利用这个接口，将其他框架的bean实例添加到spring容器中，就是把bean交由spring管理了。

一般只有在这种情况下使用，正常我们使用bean工厂，还是这个两个类：BeanFactory和ListableBeanFactory

获取方式：

```java
ApplicationContext#getAutowireCapableBeanFactory()
```

```java
//这里的beanFactory参数中就有
BeanFactoryAware#setBeanFactory(BeanFactory beanFactory)
```



如何利用这个工厂

这里security中

org.springframework.security.config.annotation.configuration.AutowireBeanFactoryObjectPostProcessor

就是通过构造器注入了AutowireCapableBeanFactory的实现类，然后调用这个实现类的方法，来初始化和注入security框架中的bean。

```java
public <T> T postProcess(T object) {
		if (object == null) {
			return null;
		}
		T result = null;
		try {
			result = (T) this.autowireBeanFactory.initializeBean(object,
					object.toString());
		}
		catch (RuntimeException e) {
			Class<?> type = object.getClass();
			throw new RuntimeException(
					"Could not postProcess " + object + " of type " + type, e);
		}
		this.autowireBeanFactory.autowireBean(object);
		if (result instanceof DisposableBean) {
			this.disposableBeans.add((DisposableBean) result);
		}
		if (result instanceof SmartInitializingSingleton) {
			this.smartSingletons.add((SmartInitializingSingleton) result);
		}
		return result;
	}
```



--------------------------------------------------------

ApplicationContextAwareProcessor 将上下文的信息注入到bean中
ApplicationListenerDetector 将实现了applicatonListener的注册到applicationContext中
LoadTimeWeaverAwareProcessor 加载时织入bean