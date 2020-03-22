数据结构的优化和内存的优化。



#### lambda表达式

- 只是一种编码风格。
- 需要满足一定格式。

**要求：**

​	1.需要定义一个函数式接口，在任何类中，只要有方法（包括构造方法），他的参数列表和返回值类型和函数式接口一致，则该函数式接口的实现体可以使用 **lambda **表达式这种方式来编写代码。

​	2.或者直接通过 **lambda** 体来实现函数式接口



```java
 /**
     * java 8 四大核心函数式接口
     * Consumer<T>
     *     void accept(T t);
     * Supplier<T>
     *     T get();
     * Function<T, R>
     *     R apply(T t);
     * Predicate<T>
     *     test(T t);
     */
```

```java
 /**
     * lambda 的其他表现形式：
     * 方法引用：（这里lambda体就是这个函数式接口的实现）
     *  就是接口中的函数，在其他的类（随便哪个类）中已经有实现的方法，
     *  这个方法要求他的返回值和参数与接口中的一致
     * 语法：
     *  对象::实例方法名
     *      规则：方法返回值和参数与接口中的一致
     *  类::静态方法
     *      规则：方法返回值和参数与接口中的一致
     *  类::实例方法名
     *      规则：第一个参数是调用者，第二个参数是被调用者
     *
     *
     *   构造器引用：
     *   ClassName::new
     *      规则：构造器中的参数列表和接口的一致
     *
     *  数组引用：
     *      Type[]::new
     */
```



#### Stream API

就像写SQL一样。

##### 特征：

- 1.Stream不存储数据
- 2.不会改变源对象，会产生一个新的流。
- 3.延迟加载：只有终止操作后，才会全部执行其中的操作。

##### 获取Stream方式

- java.util.Collection#stream

- Arrays.stream(array[])

- java.util.stream.Stream#of(T...)

- java.util.stream.Stream#iterate

- java.util.stream.Stream#generate


#### 思考Stream的这些特点可以使用在哪些场景下

