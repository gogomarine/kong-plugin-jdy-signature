## 说明

本插件用于简道云的Webhook推送时的签名认证，减少在App中重复写这个逻辑的问题；文档参考[简道云-Webhook-开发指南](https://hc.jiandaoyun.com/open/11507)，截止到2022-10-25；

[lua-nginx-module - 文档](http://man.hubwiz.com/docset/OpenResty.docset/Contents/Resources/Documents/lua-nginx-module.html#ngxhmac_sha1)，或者 [Lua_Nginx_API](https://openresty-reference.readthedocs.io/en/latest/Lua_Nginx_API/)

[KONG Plugin 开发的官方文档](https://docs.konghq.com/gateway/latest/plugin-development/pdk/kong.client/)

### 使用说明

在 Services / Routes 里面配置 Plugins 

- clock skew - 允许多少秒的时差（单位是秒）
- jdy consumer id - 这个是跟 Consumers 关联，需要建立 hmac 的类型密钥（会获取该类型密钥），进行签名校验；因为每个路径都不一样，所以独立设置。虽然是根据不同的表配置，但是密钥可以统一配置一个。方便在后台一起管理