# opencode-deveco-auth

Huawei DevEco Code 认证插件 for [opencode](https://opencode.ai)。提供 OAuth 登录、自动 token 刷新和模型发现。

## 安装

在 `opencode.json` 中添加：

```json
{
  "plugin": ["deveco-auth@git+https://github.com/KaiSiMai/opencode-deveco-auth.git"]
}
```

重启 opencode，启动时自动安装。

## 使用

安装后在 TUI 中按 `CTRL+P` > `Connect provider` 选 `DevEco Code` 登录，浏览器打开华为 DevEco 登录页。登录成功后，DevEco Code 模型即可使用。

插件自动处理 token 刷新——过期 token 透明刷新并持久化。

## 原理

- 通过 opencode 插件系统注册 `deveco` provider
- OAuth 流程走华为 DevEco Code 网页登录
- Token 缓存到文件 (`~/.config/opencode/opencode-deveco-auth/jwt.json`)
- 自动 401/403 重试 + token 重新获取

## License

MIT
