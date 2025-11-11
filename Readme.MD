# DH.Permissions - JWT权限类库

DH框架的JWT权限类库，提供完整的JWT Token生成、校验、刷新等功能。

## 功能特性

- ✅ JWT Token生成与管理
- ✅ Access Token & Refresh Token双令牌机制
- ✅ Token校验与验证
- ✅ 设备绑定与跨设备检测
- ✅ 用户会话管理
- ✅ 灵活的配置选项
- ✅ 完整的错误处理机制

## 快速开始

### 1. 安装

```bash
dotnet add package DH.Permissions
```

### 2. 配置

在 `appsettings.json` 中添加JWT配置：

```json
{
  "JwtOptions": {
    "Secret": "your-super-secret-key-at-least-16-characters",
    "Issuer": "YourAppName",
    "Audience": "YourAppUsers",
    "AccessExpireMinutes": 30,
    "RefreshExpireMinutes": 10080
  }
}
```

### 3. 注册服务

在 `Program.cs` 或 `Startup.cs` 中注册服务：

```csharp
using DH.Permissions.Extensions;

// 方式1：从配置文件读取
builder.Services.AddJwt(builder.Configuration);

// 方式2：直接配置
builder.Services.AddJwt(options =>
{
    options.Secret = "your-super-secret-key-at-least-16-characters";
    options.Issuer = "YourAppName";
    options.Audience = "YourAppUsers";
    options.AccessExpireMinutes = 30;
    options.RefreshExpireMinutes = 10080;
});
```

添加认证和授权中间件：

```csharp
var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// 可选：使用自定义JWT授权中间件
app.UseJwtCustomerAuthorize(option =>
{
    // 配置匿名路径
    option.AnonymousPaths = new[] { "/api/auth/login", "/api/auth/register" };
    
    // 自定义负载验证
    option.ValidatePayload = (payload, jwtOptions) =>
    {
        // 可以在这里添加自定义验证逻辑
        return true;
    };
});
```

## 使用示例

### 生成Token

```csharp
using DH.Permissions.Identity.JwtBearer;

public class AuthController : ControllerBase
{
    private readonly IJsonWebTokenBuilder _tokenBuilder;

    public AuthController(IJsonWebTokenBuilder tokenBuilder)
    {
        _tokenBuilder = tokenBuilder;
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        // 验证用户名密码...
        
        // 构建Token负载
        var payload = new Dictionary<String, String>
        {
            ["sub"] = userId,              // 用户ID（必需）
            ["name"] = username,           // 用户名
            ["role"] = "Admin",            // 角色
            ["clientId"] = deviceId,       // 设备ID（必需）
            ["clientType"] = "admin",      // 客户端类型
            ["From"] = "WebApp"            // 来源标识（必需）
        };

        // 生成Token
        var token = _tokenBuilder.Create(payload);

        return Ok(new
        {
            accessToken = token.AccessToken,
            refreshToken = token.RefreshToken,
            accessTokenExpires = token.AccessTokenUtcExpires,
            refreshTokenExpires = token.RefreshUtcExpires
        });
    }
}
```

### Token校验

#### 方式1：简单校验（推荐）

```csharp
using DH.Permissions.Identity.JwtBearer;

public class TokenValidationExample
{
    private readonly IJsonWebTokenValidator _tokenValidator;

    public TokenValidationExample(IJsonWebTokenValidator tokenValidator)
    {
        _tokenValidator = tokenValidator;
    }

    /// <summary>
    /// 简单快速校验Token是否有效
    /// </summary>
    public Boolean QuickValidate(String token)
    {
        // 使用注入的默认配置进行校验
        // 自动验证：签名、过期时间、生效时间
        return _tokenValidator.IsValidToken(token);
    }

    /// <summary>
    /// 校验Token并获取详细结果
    /// </summary>
    public void ValidateWithDetails(String token)
    {
        var result = _tokenValidator.IsValidTokenWithResult(token);
        
        if (result.IsValid)
        {
            Console.WriteLine("Token有效！");
            Console.WriteLine($"用户ID: {result.Payload["sub"]}");
            Console.WriteLine($"用户名: {result.Payload["name"]}");
            Console.WriteLine($"角色: {result.Payload["role"]}");
            Console.WriteLine($"验证时间: {result.ValidatedAt}");
        }
        else
        {
            Console.WriteLine($"Token无效: {result.ErrorMessage}");
        }
    }
}
```

#### 方式2：自定义验证逻辑

```csharp
using DH.Permissions.Identity.JwtBearer;
using Pek.Security;

public class CustomTokenValidation
{
    private readonly IJsonWebTokenValidator _tokenValidator;

    public CustomTokenValidation(IJsonWebTokenValidator tokenValidator)
    {
        _tokenValidator = tokenValidator;
    }

    /// <summary>
    /// 带自定义验证逻辑的Token校验
    /// </summary>
    public Boolean ValidateWithCustomLogic(String token, JwtOptions options)
    {
        return _tokenValidator.Validate(token, options, (payload, opt) =>
        {
            // 自定义验证1：检查用户角色
            if (!payload.ContainsKey("role") || payload["role"] != "Admin")
            {
                Console.WriteLine("用户角色验证失败");
                return false;
            }

            // 自定义验证2：检查来源
            if (!payload.ContainsKey("From") || payload["From"] != "WebApp")
            {
                Console.WriteLine("来源验证失败");
                return false;
            }

            // 自定义验证3：检查设备ID
            if (!payload.ContainsKey("clientId"))
            {
                Console.WriteLine("缺少设备ID");
                return false;
            }

            return true;
        });
    }

    /// <summary>
    /// 自定义验证并获取详细结果
    /// </summary>
    public TokenValidationResult ValidateWithCustomLogicAndResult(String token, JwtOptions options)
    {
        return _tokenValidator.ValidateWithResult(token, options, (payload, opt) =>
        {
            // 检查用户是否被禁用（示例：从数据库查询）
            var userId = payload.GetOrDefault("sub", String.Empty);
            // var isUserActive = _userService.IsUserActive(userId);
            // return isUserActive;
            
            return true;
        });
    }
}
```

### 刷新Token

```csharp
public class RefreshTokenExample
{
    private readonly IJsonWebTokenBuilder _tokenBuilder;

    public RefreshTokenExample(IJsonWebTokenBuilder tokenBuilder)
    {
        _tokenBuilder = tokenBuilder;
    }

    [HttpPost("refresh")]
    public IActionResult RefreshToken([FromBody] String refreshToken)
    {
        try
        {
            // 使用refresh token换取新的token对
            var newToken = _tokenBuilder.Refresh(refreshToken);

            return Ok(new
            {
                accessToken = newToken.AccessToken,
                refreshToken = newToken.RefreshToken,
                accessTokenExpires = newToken.AccessTokenUtcExpires,
                refreshTokenExpires = newToken.RefreshUtcExpires
            });
        }
        catch (JwtRefreshException ex)
        {
            // 刷新失败，需要重新登录
            return Unauthorized(new { message = ex.Message, code = ex.ErrCode });
        }
    }

    /// <summary>
    /// 带延时清理的Token刷新
    /// </summary>
    public IActionResult RefreshWithDelay([FromBody] String refreshToken)
    {
        try
        {
            // 刷新Token，旧Token延迟60秒后清理（允许短暂的宽限期）
            var newToken = _tokenBuilder.Refresh(refreshToken, expire: 60);
            
            return Ok(new
            {
                accessToken = newToken.AccessToken,
                refreshToken = newToken.RefreshToken
            });
        }
        catch (JwtRefreshException ex)
        {
            return Unauthorized(new { message = ex.Message });
        }
    }
}
```

### 用户Token管理

```csharp
using DH.Permissions.Identity.JwtBearer;

public class UserTokenManagementExample
{
    private readonly IUserTokenService _userTokenService;

    public UserTokenManagementExample(IUserTokenService userTokenService)
    {
        _userTokenService = userTokenService;
    }

    /// <summary>
    /// 强制用户下线（清除所有Token）
    /// </summary>
    public async Task ForceLogout(String userId)
    {
        await _userTokenService.ClearUserTokenAsync(userId);
    }

    /// <summary>
    /// 清除用户指定设备的Token
    /// </summary>
    public async Task LogoutDevice(String userId, String deviceId, String deviceType = "admin")
    {
        await _userTokenService.ClearDeviceTokenAsync(userId, deviceType, deviceId);
    }

    /// <summary>
    /// 检查Token是否仍然有效（未被清除）
    /// </summary>
    public async Task<Boolean> IsTokenStillValid(String token)
    {
        return await _userTokenService.IsTokenValidAsync(token);
    }
}
```

### 在控制器中使用授权

```csharp
using Microsoft.AspNetCore.Authorization;

[ApiController]
[Route("api/[controller]")]
public class SecureController : ControllerBase
{
    // 方式1：使用标准Authorize特性
    [Authorize]
    [HttpGet("protected")]
    public IActionResult ProtectedEndpoint()
    {
        var userId = User.FindFirst("sub")?.Value;
        var userName = User.FindFirst("name")?.Value;
        
        return Ok(new { userId, userName });
    }

    // 方式2：使用JWT策略
    [Authorize(Policy = "jwt")]
    [HttpGet("jwt-protected")]
    public IActionResult JwtProtectedEndpoint()
    {
        return Ok("This endpoint is protected by JWT");
    }

    // 方式3：使用自定义JWT授权特性
    [JwtAuthorize]
    [HttpGet("custom-protected")]
    public IActionResult CustomProtectedEndpoint()
    {
        return Ok("This endpoint uses custom JWT authorization");
    }
}
```

### 完整示例：登录-验证-刷新-登出

```csharp
[ApiController]
[Route("api/[controller]")]
public class AuthenticationController : ControllerBase
{
    private readonly IJsonWebTokenBuilder _tokenBuilder;
    private readonly IJsonWebTokenValidator _tokenValidator;
    private readonly IUserTokenService _userTokenService;

    public AuthenticationController(
        IJsonWebTokenBuilder tokenBuilder,
        IJsonWebTokenValidator tokenValidator,
        IUserTokenService userTokenService)
    {
        _tokenBuilder = tokenBuilder;
        _tokenValidator = tokenValidator;
        _userTokenService = userTokenService;
    }

    /// <summary>
    /// 用户登录
    /// </summary>
    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        // TODO: 验证用户凭据
        // var user = _userService.ValidateCredentials(request.Username, request.Password);
        
        var userId = "user123";
        var userName = request.Username;
        var deviceId = HttpContext.Request.Headers["X-Device-Id"].ToString();

        var payload = new Dictionary<String, String>
        {
            ["sub"] = userId,
            ["name"] = userName,
            ["role"] = "User",
            ["clientId"] = deviceId,
            ["clientType"] = "web",
            ["From"] = "WebApp"
        };

        var token = _tokenBuilder.Create(payload);

        return Ok(new
        {
            success = true,
            data = new
            {
                accessToken = token.AccessToken,
                refreshToken = token.RefreshToken,
                expiresIn = token.AccessTokenUtcExpires
            }
        });
    }

    /// <summary>
    /// 验证Token
    /// </summary>
    [HttpPost("validate")]
    public IActionResult ValidateToken([FromBody] String token)
    {
        var result = _tokenValidator.IsValidTokenWithResult(token);

        if (result.IsValid)
        {
            return Ok(new
            {
                valid = true,
                userId = result.Payload.GetOrDefault("sub"),
                userName = result.Payload.GetOrDefault("name"),
                role = result.Payload.GetOrDefault("role")
            });
        }

        return BadRequest(new
        {
            valid = false,
            error = result.ErrorMessage
        });
    }

    /// <summary>
    /// 刷新Token
    /// </summary>
    [HttpPost("refresh")]
    public IActionResult RefreshToken([FromBody] RefreshTokenRequest request)
    {
        try
        {
            var newToken = _tokenBuilder.Refresh(request.RefreshToken);

            return Ok(new
            {
                success = true,
                data = new
                {
                    accessToken = newToken.AccessToken,
                    refreshToken = newToken.RefreshToken,
                    expiresIn = newToken.AccessTokenUtcExpires
                }
            });
        }
        catch (JwtRefreshException ex)
        {
            return Unauthorized(new
            {
                success = false,
                message = ex.Message,
                code = ex.ErrCode
            });
        }
    }

    /// <summary>
    /// 用户登出
    /// </summary>
    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        var userId = User.FindFirst("sub")?.Value;
        
        if (!String.IsNullOrEmpty(userId))
        {
            await _userTokenService.ClearUserTokenAsync(userId);
        }

        return Ok(new { success = true, message = "已成功登出" });
    }

    /// <summary>
    /// 登出指定设备
    /// </summary>
    [Authorize]
    [HttpPost("logout-device")]
    public async Task<IActionResult> LogoutDevice([FromBody] String deviceId)
    {
        var userId = User.FindFirst("sub")?.Value;
        var deviceType = User.FindFirst("clientType")?.Value ?? "web";

        if (!String.IsNullOrEmpty(userId) && !String.IsNullOrEmpty(deviceId))
        {
            await _userTokenService.ClearDeviceTokenAsync(userId, deviceType, deviceId);
        }

        return Ok(new { success = true, message = "设备已登出" });
    }
}
```

## 配置选项说明

### JwtOptions

| 属性 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| Secret | String | - | JWT签名密钥（必需，建议至少16字符） |
| Issuer | String | - | 令牌颁发者 |
| Audience | String | - | 令牌接收者 |
| AccessExpireMinutes | Double | 30 | 访问令牌有效期（分钟） |
| RefreshExpireMinutes | Double | 10080 | 刷新令牌有效期（分钟，默认7天） |

## API接口

### IJsonWebTokenBuilder

- `Create(payload)` - 创建Token
- `Create(payload, refreshExpireMinutes, accessExpireMinutes)` - 创建自定义过期时间的Token
- `Refresh(refreshToken)` - 刷新Token
- `Refresh(refreshToken, expire)` - 延时清理的Token刷新

### IJsonWebTokenValidator

- `IsValidToken(token)` - 简单校验Token（推荐）
- `IsValidTokenWithResult(token)` - 校验并返回详细结果
- `Validate(token, options, validatePayload)` - 自定义验证逻辑
- `ValidateWithResult(token, options, validatePayload)` - 自定义验证并返回结果

### IUserTokenService

- `ClearUserTokenAsync(userId)` - 清除用户所有Token
- `ClearDeviceTokenAsync(userId, deviceType, deviceId)` - 清除指定设备Token
- `IsTokenValidAsync(token)` - 检查Token是否有效

## 错误处理

### JwtRefreshException

刷新Token失败时抛出，包含错误码9994。

```csharp
try
{
    var newToken = _tokenBuilder.Refresh(refreshToken);
}
catch (JwtRefreshException ex)
{
    // ex.Message - 错误消息
    // ex.ErrCode - 错误码（9994）
    Console.WriteLine($"刷新失败: {ex.Message}");
}
```

## 安全建议

1. **Secret密钥**：使用足够复杂的密钥（建议32字符以上），不要硬编码在代码中
2. **HTTPS**：生产环境必须使用HTTPS传输Token
3. **Token存储**：客户端不要将Token存储在LocalStorage，推荐使用HttpOnly Cookie
4. **过期时间**：AccessToken设置较短（15-30分钟），RefreshToken可设置较长（7-30天）
5. **设备绑定**：启用设备ID验证，防止Token被盗用
6. **及时清理**：用户修改密码或敏感操作后，清除所有Token强制重新登录

## 更多示例

查看 `Examples/` 目录获取更多使用示例：

- `TokenValidationOptimizationExample.cs` - Token验证优化示例
- `JwtOptimizationUsageExample.cs` - JWT优化使用示例
- `UserTokenServiceTest.cs` - 用户Token服务测试
- `TokenRefreshControllerExample.cs` - Token刷新控制器示例

## 故障排查: 403 Forbidden（接口返回403）

如果接口在传入正确 Token 的情况下返回 403（Forbidden），通常说明请求已通过身份认证，但**未通过授权策略/自定义校验**。下面是常见原因和排查步骤：

1. Token 有效但 Payload 未通过自定义验证。
    - 触发点：`IJsonWebTokenValidator.ValidateWithResult(..., validatePayload)` 或授权处理器 `JsonWebTokenAuthorizationHandler`。
    - 排查：检查 `validatePayload` 回调实现，确认必要字段（如 `sub`, `clientId`, `From` 等）存在并正确。

2. 设备ID 不匹配或禁止跨设备使用。
    - 触发点：在授权处理器 `JsonWebTokenAuthorizationHandler` 中，会比较 token 中的 `clientId` 与当前设备ID（`DeviceIdCache.GetDeviceId`）。
    - 排查：确认 `PekSysSetting.Current.AllowJwtCrossDevice` 是否为 `true`（开发模式），或 token 中的 `clientId` 与设备ID一致。服务器端会写日志 `SecurityLogger.LogDeviceIdMismatch`。

3. 单设备登录限制（SingleDeviceEnabled）被触发。
    - 触发点：`JsonWebTokenAuthorizationHandler` 在 `SingleDeviceEnabled` 开启时校验绑定设备信息（`IJsonWebTokenStore.GetUserDeviceToken`），若不一致则拒绝。
    - 排查：在 token 生成时是否保存了正确的设备绑定信息，或检查 `IJsonWebTokenStore` 中的记录。

4. Token 在 TokenStore 中不存在或已失效（但仍被认证）
    - 触发点：授权处理器会通过 `_tokenStore.GetToken(token)` 来确保 token 在服务端存储（例如支持下线、清除）。如果为空或过期会 `context.Fail()`。
    - 排查：确认 token 是否存在于 `IJsonWebTokenStore`，是否被清除或过期。

5. `From` 字段不匹配（自定义 JwtAuthorize 特性）
    - 触发点：`JwtAuthorizeAttribute` 指定某个 `From` 值，若 token 中 `From` 不一致则授权失败。
    - 排查：确认 Controller/Action 使用 `JwtAuthorize` 时指定的 `From` 值与 token 中的 `From` 一致。

6. 其他自定义逻辑或权限校验失败
    - 排查：审查 `validatePayload` 和任何自定义授权逻辑；检查是否有额外的要求（角色、范围等）导致授权失败。

调试与排查建议

1. 打开服务端日志，定位 `SecurityLogger` 相关条目（例如设备 ID 不匹配会记录）。
2. 在开发环境中设置 `JwtOptions.ThrowEnabled = true`（或者 `ThrowEnabled` 对应的配置），可以让授权处理器抛出 `UnauthorizedAccessException`，便于查看明确异常原因（仅在开发时打开）。
3. 使用 `TokenValidationCache` 缓存结果时，确保没有触发缓存不一致导致的授权问题；清理缓存后重试。
4. 对于 403 响应，优先在 `JsonWebTokenAuthorizationHandler` 的 `ResultHandle` 分支中查找 `context.Fail()` 的条件：签名/过期校验通过但自定义校验、设备绑定、单设备校验失败。
5. 在 `Startup` 中添加一个中间件用于调试：当响应状态为 403 时，打印 `HttpContext.Items["AuthFailureReason"]` 或 `AuthFailureCode` 的值（授权处理器会在某些情况下写入这两个字段）。

示例：记录 403 原因的调试中间件

```csharp
public class JwtAuthFailureLoggingMiddleware
{
     private readonly RequestDelegate _next;

     public JwtAuthFailureLoggingMiddleware(RequestDelegate next) => _next = next;

     public async Task Invoke(HttpContext context)
     {
          await _next(context);

          if (context.Response.StatusCode == StatusCodes.Status403Forbidden)
          {
                // 探查授权失败信息（若授权处理器设置了）
                if (context.Items.TryGetValue("AuthFailureReason", out var reason))
                {
                     // 记录日志或输出到控制台
                     Console.WriteLine($"JWT Auth Failure Reason: {reason}");
                }

                if (context.Items.TryGetValue("AuthFailureCode", out var code))
                {
                     Console.WriteLine($"JWT Auth Failure Code: {code}");
                }
          }
     }
}

// 注册方式（仅用于排查）
// app.UseMiddleware<JwtAuthFailureLoggingMiddleware>();
```

其它快速校验项

- 确认 Authorization Header: `Authorization: Bearer <token>`
- 确认服务端 `JwtOptions.Secret`、`Issuer`、`Audience` 与 token 一致
- 确认 token 未过期（注意 `exp` 单位应为秒）
- 确认 payload 中 `sub`、`clientId`、`From` 等字段是否缺失或错误
- 如果使用 `UseJwtCustomerAuthorize`（自定义中间件），它会直接抛 Unauthorized （401）而不是返回 403

如果你愿意，我可以把这个调试中间件整合为一个示例并加入到 `Examples/` 目录，也可以在 README 中加入示例日志截图或命令行测试脚本。

## 许可证

MIT License
