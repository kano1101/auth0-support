# auth0-support usage

環境変数に下記の適切な値を設定してください。
```
AUTH0_DOMAIN="your-auth0-domain"
AUTH0_CLIENT_ID="your-auth0-client-id"
AUTH0_CLIENT_SECRET="your-auth0-client-secret"
AUTH0_AUDIENCE="your-auth0-audience"
JWT_SECRET="your-jwt-secret"
AUTH0_CALLBACK_URL="http://localhost:3000/auth/callback"
FALLBACK_URI="http://localhost:3000"
ALLOWED_REDIRECT_URIS="http://localhost:3000,http://localhost:8000"
RUST_LOG="INFO"
```

＜注意＞環境変数を正しく読み込むために、set_varは可能な限り使用しないでください。
