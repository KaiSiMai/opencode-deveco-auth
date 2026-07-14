# opencode-deveco-auth

Huawei DevEco Code auth plugin for [opencode](https://opencode.ai). OAuth login, automatic token refresh, and model discovery.

## Install

Add to `opencode.json`:

```json
{
  "plugin": ["deveco-auth@git+https://github.com/KaiSiMai/opencode-deveco-auth.git"]
}
```

Restart opencode — installs automatically on startup.

## Usage

After installation, press `CTRL+P` > `Connect provider` and select `DevEco Code`. A browser opens for Huawei DevEco login. After success, DevEco Code models become available.

Token refresh is handled transparently — expired tokens are refreshed and persisted automatically.

## How It Works

- Registers `deveco` provider via opencode plugin system
- OAuth flow via Huawei DevEco Code web login
- Token cache at `~/.config/opencode/opencode-deveco-auth/jwt.json`
- Automatic 401/403 retry with token re-fetch

## License

MIT
