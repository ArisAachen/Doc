
``` c
PolkitSubject *
polkit_backend_session_monitor_get_session_for_subject (PolkitBackendSessionMonitor *monitor,
                                                        PolkitSubject               *subject,
                                                        GError                     **error)
根据dbus号码获取当前对应的进程生成一个session
```

``` c
PolkitSubject是一个Polkit基础类

PolkitSubject *
polkit_subject_new_for_gvariant (GVariant  *variant,
                                 GError    **error)
根据CheckAuth传入的参数生成PolkitSubject基础类
参数可能是system-bus:{name:":1111"}

PolkitSubject *
polkit_system_bus_name_new (const gchar *name)
根据传入的dbus号生成一个PolkitSubject，实际类应该是PolkitSystemBusName类

```


``` c
on_bus_acquired->导出PolicyKit,on_bus_acquired->polkit_backend_authority_register->polkit_backend_authority_get

gpointer
polkit_backend_authority_register (PolkitBackendAuthority   *authority,
                                   GDBusConnection          *connection,
                                   const gchar              *object_path,
                                   GError                  **error) 
{
    // 新建一个server 传到后续接口server_handle_method_call的userdata
    Server *server;
    // 其中的authority为全局静态变量
    static PolkitBackendAuthority *authority = NULL;
    ... ... 
    // 注册了导出方法
  server->authority_registration_id = g_dbus_connection_register_object (server->connection,
                                                                         object_path,
                                                                         g_dbus_node_info_lookup_interface (server->introspection_info, "org.freedesktop.PolicyKit1.Authority"),
                                                                         &server_vtable,
                                                                         server,
                                                                         NULL,
                                                                         error);
        
    ... ...
}

```

``` c
// polkit_backend_null_authority模块注册
g_io_module_load (GIOModule *module)->polkit_backend_null_authority_register (module){read config file:nullbackend.conf.d};

``` 