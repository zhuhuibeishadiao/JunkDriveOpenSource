# Wow Injecter
目录:
App:  
  应用层通信程序源代码
  
DriverInjectDll:  
  Loader：内存加载dll shellcode模板(无需修改)  
  MyDll：测试Dll DllMain中处理了wow反注入 并模拟创建一个线程  
  bin：所有代码生成的成品  
  其它:内核注入源代码  
  
### 注入：
驱动使用apc注入(已shellcode加载dll 实现dll无模块化)  
保护内存被查询：使用infinityhook(已解决hook之后几分钟失效的问题 )拦截ZwQueryVirtualMemory过滤掉我们注入的进程中可读可写可执行的内存(如果DLL中要申请内存,属性需要填写可读可写可执行)    

#### wow反注入：
wow 使用tls进行监控线程创建,已处理(见MyDll AntiAntiInject)  

### 编译：
默认使用vs2017 + wdk/sdk 10.17763 如没有此编译环境 改项目属性即可  
