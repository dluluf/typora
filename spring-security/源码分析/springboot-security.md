```java
/**
 * Dynamically determines which imports to include using the
 * {@link EnableGlobalMethodSecurity} annotation.
 * 使用@EnableGlobalMethodSecurity注解，动态的决定需要导入的类
 * 这里导入的类是哪些类呢：
 *	 1.根据注解 @EnableGlobalMethodSecurity 属性的值，加载相关的处理类
 *   2.如果这个类不是继承 GlobalMethodSecurityConfiguration.class,则导入	
 *      GlobalMethodSecurityConfiguration 这个类。
 */
final class GlobalMethodSecuritySelector implements ImportSelector {
```

