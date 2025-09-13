using DH.Permissions.Identity.JwtBearer;
using DH.Permissions.Identity.JwtBearer.Internal;
using DH.Permissions.Security;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;

using NewLife;
using NewLife.Log;

using Pek;
using Pek.Configs;
using Pek.Helpers;
using Pek.Security;

namespace DH.Permissions.Authorization.Policies;

/// <summary>
/// Jwt授权处理器
/// </summary>
public class JsonWebTokenAuthorizationHandler : AuthorizationHandler<JsonWebTokenAuthorizationRequirement>
{
    /// <summary>
    /// Jwt选项配置
    /// </summary>
    private readonly JwtOptions _options;

    /// <summary>
    /// Jwt令牌校验器
    /// </summary>
    private readonly IJsonWebTokenValidator _tokenValidator;

    /// <summary>
    /// Jwt令牌存储器
    /// </summary>
    private readonly IJsonWebTokenStore _tokenStore;

    private readonly IHttpContextAccessor _accessor;

    /// <summary>
    /// 初始化一个<see cref="JsonWebTokenAuthorizationHandler"/>类型的实例
    /// </summary>
    /// <param name="options">Jwt选项配置</param>
    /// <param name="tokenValidator">Jwt令牌校验器</param>
    /// <param name="tokenStore">Jwt令牌存储器</param>
    /// <param name="accessor">HttpContext</param>
    public JsonWebTokenAuthorizationHandler(
        IHttpContextAccessor accessor
        , IOptions<JwtOptions> options
        , IJsonWebTokenValidator tokenValidator
        , IJsonWebTokenStore tokenStore)
    {
        _options = options.Value;
        _tokenValidator = tokenValidator;
        _tokenStore = tokenStore;
        _accessor = accessor;
    }

    /// <summary>
    /// 重载异步处理
    /// </summary>
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, JsonWebTokenAuthorizationRequirement requirement)
    {
        if (_options.ThrowEnabled)
        {
            ThrowExceptionHandle(context, requirement);
            return;
        }
        ResultHandle(context, requirement);
        await Task.FromResult(0).ConfigureAwait(false);
    }

    /// <summary>
    /// 抛异常处理方式
    /// </summary>
    protected virtual void ThrowExceptionHandle(AuthorizationHandlerContext context,
        JsonWebTokenAuthorizationRequirement requirement)
    {
        var httpContext = (context.Resource as AuthorizationFilterContext)?.HttpContext;
        if (httpContext == null)
            return;
        // 未登录而被拒绝
        var result = httpContext.Request.Headers.TryGetValue("Authorization", out var authorizationHeader);
        if (!result || String.IsNullOrWhiteSpace(authorizationHeader))
            throw new UnauthorizedAccessException("未授权，请传递Header头的Authorization参数");
        var token = authorizationHeader.ToString().Split(' ').Last().Trim();

        // 优化：一次性获取Token对象，避免重复缓存查询
        var accessToken = _tokenStore.GetToken(token);
        if (accessToken == null)
            throw new UnauthorizedAccessException("未授权，无效参数");

        // 尝试从缓存获取验证结果，如果没有则进行验证并缓存
        var validationResult = TokenValidationCache.GetCachedResult(httpContext, token);
        if (validationResult == null)
        {
            validationResult = _tokenValidator.ValidateWithResult(token, _options, requirement.ValidatePayload);
            TokenValidationCache.SetCachedResult(httpContext, token, validationResult);
        }

        if (!validationResult.IsValid)
            throw new UnauthorizedAccessException("验证失败，请查看传递的参数是否正确或是否有权限访问该地址。");

        // 检查Token是否过期（使用已获取的accessToken对象）
        if (accessToken.IsExpired())
            throw new UnauthorizedAccessException("Token已过期");

        var payload = validationResult.Payload;

        // 兼容旧版本：校验From字段
        var endpoint = httpContext.GetEndpoint();
        var fromAttribute = endpoint?.Metadata.GetMetadata<JwtAuthorizeAttribute>();
        var requiredFrom = fromAttribute?.From;
        payload.TryGetValue("From", out var tokenFrom);
        //XTrace.WriteLine($"判断获取到的数据：{tokenFrom}:{requiredFrom}");
        if (!requiredFrom.IsNullOrWhiteSpace())
        {
            if (!String.Equals(tokenFrom, requiredFrom, StringComparison.OrdinalIgnoreCase))
            {
                throw new UnauthorizedAccessException($"Token来源不符，要求From={requiredFrom}, 实际From={tokenFrom}");
            }
        }

        // 设备ID验证：验证Token中的clientId与当前设备ID是否一致
        var currentDeviceId = DeviceIdCache.GetDeviceId(httpContext);
        var tokenClientId = payload.TryGetValue("clientId", out var clientIdObj) ? clientIdObj as String : String.Empty;
        var allowCrossDevice = PekSysSetting.Current.AllowJwtCrossDevice;

        if (!currentDeviceId.IsNullOrEmpty() && !tokenClientId.IsNullOrEmpty() && tokenClientId != currentDeviceId && !allowCrossDevice)
        {
            var userId = payload.GetOrDefault("sub", "未知").ToString();
            SecurityLogger.LogDeviceIdMismatch(httpContext, tokenClientId, currentDeviceId, userId, "JsonWebTokenAuthorizationHandler_ThrowExceptionHandle", new { Action = "TokenValidation", Method = "ThrowException" });
            if (!SecuritySetting.Current.AllowCrossDevice)
                throw new UnauthorizedAccessException($"设备标识不匹配，Token无法在此设备使用");
        }
        else if (!currentDeviceId.IsNullOrEmpty() && !tokenClientId.IsNullOrEmpty() && tokenClientId != currentDeviceId && allowCrossDevice)
        {
            var userId = payload.GetOrDefault("sub", "未知").ToString();
            XTrace.WriteLine($"[开发模式] 允许跨设备Token验证: tokenClientId={tokenClientId}, currentDeviceId={currentDeviceId}, userId={userId}");
        }

        if (_options.SingleDeviceEnabled)
        {
            var bindDeviceInfo = _tokenStore.GetUserDeviceToken(payload["sub"].SafeString(), payload["clientType"].SafeString());
            if (bindDeviceInfo.DeviceId != payload["clientId"].SafeString())
                throw new UnauthorizedAccessException("该账号已在其它设备登录");
        }
        var isAuthenticated = httpContext.User.Identity.IsAuthenticated;
        if (!isAuthenticated)
            return;
        context.Succeed(requirement);
    }

    /// <summary>
    /// 结果处理方式
    /// </summary>
    protected virtual void ResultHandle(AuthorizationHandlerContext context,
        JsonWebTokenAuthorizationRequirement requirement)
    {
        var httpContext = _accessor.HttpContext;

        httpContext ??= Pek.Webs.HttpContext.Current;
        if (httpContext == null)
            return;

        // 未登录而被拒绝
        var result = httpContext.Request.Headers.TryGetValue("Authorization", out var authorizationHeader);

        if (!result || String.IsNullOrWhiteSpace(authorizationHeader))
        {
            context.Fail();
            return;
        }

        var token = authorizationHeader.ToString().Split(' ').Last().Trim();

        // 优化：一次性获取Token对象，避免重复缓存查询
        var accessToken = _tokenStore.GetToken(token);
        if (accessToken == null)
        {
            context.Fail();
            return;
        }

        // 尝试从缓存获取验证结果，如果没有则进行验证并缓存
        var validationResult = TokenValidationCache.GetCachedResult(httpContext, token);
        if (validationResult == null)
        {
            validationResult = _tokenValidator.ValidateWithResult(token, _options, requirement.ValidatePayload);
            TokenValidationCache.SetCachedResult(httpContext, token, validationResult);
        }

        if (!validationResult.IsValid)
        {
            context.Fail();
            return;
        }

        // 检查Token是否过期（使用已获取的accessToken对象）
        if (accessToken.IsExpired())
        {
            context.Fail();
            return;
        }

        var payload = validationResult.Payload;

        // 兼容旧版本：校验From字段
        var endpoint = httpContext.GetEndpoint();
        var fromAttribute = endpoint?.Metadata.GetMetadata<JwtAuthorizeAttribute>();
        var requiredFrom = fromAttribute?.From;
        payload.TryGetValue("From", out var tokenFrom);
        //XTrace.WriteLine($"判断获取到的数据：{tokenFrom}:{requiredFrom}");
        if (!requiredFrom.IsNullOrWhiteSpace())
        {
            if (!String.Equals(tokenFrom, requiredFrom, StringComparison.OrdinalIgnoreCase))
            {
                context.Fail();
                return;
            }
        }

        // 设备ID验证：验证Token中的clientId与当前设备ID是否一致
        var currentDeviceId = DeviceIdCache.GetDeviceId(httpContext);
        var tokenClientId = payload.TryGetValue("clientId", out var clientIdObj) ? clientIdObj as String : String.Empty;
        var allowCrossDevice = PekSysSetting.Current.AllowJwtCrossDevice;

        if (!currentDeviceId.IsNullOrEmpty() && !tokenClientId.IsNullOrEmpty() && tokenClientId != currentDeviceId && !allowCrossDevice)
        {
            var userId = payload.GetOrDefault("sub", "未知").ToString();
            SecurityLogger.LogDeviceIdMismatch(httpContext, tokenClientId, currentDeviceId, userId, "JsonWebTokenAuthorizationHandler_ResultHandle", new { Action = "TokenValidation", Method = "ResultHandle" });

            if (!SecuritySetting.Current.AllowCrossDevice)
            {
                httpContext.Items["AuthFailureReason"] = "设备标识不匹配，Token无法在此设备使用";
                httpContext.Items["AuthFailureCode"] = 40005;
                context.Fail();
                return;
            }
        }
        else if (!currentDeviceId.IsNullOrEmpty() && !tokenClientId.IsNullOrEmpty() && tokenClientId != currentDeviceId && allowCrossDevice)
        {
            var userId = payload.GetOrDefault("sub", "未知").ToString();
            XTrace.WriteLine($"[开发模式] 允许跨设备Token验证: tokenClientId={tokenClientId}, currentDeviceId={currentDeviceId}, userId={userId}");
        }

        // 单设备登录
        if (_options.SingleDeviceEnabled)
        {
            var bindDeviceInfo = _tokenStore.GetUserDeviceToken(payload["sub"].SafeString(), payload["clientType"].SafeString());
            if (bindDeviceInfo.DeviceId != payload["clientId"].SafeString())
            {
                httpContext.Items["AuthFailureReason"] = "该账号已在其它设备登录";
                httpContext.Items["AuthFailureCode"] = 40004;
                context.Fail();
                return;
            }
        }

        var isAuthenticated = httpContext.User.Identity.IsAuthenticated;
        if (!isAuthenticated)
            return;

        httpContext.Items["clientId"] = payload["clientId"];

        context.Succeed(requirement);
    }


}
