using DH.Permissions.Identity.JwtBearer;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

using NewLife;
using NewLife.Log;
using NewLife.Serialization;

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
        XTrace.WriteLineSafe($"JWT授权开始处理，ThrowEnabled={_options.ThrowEnabled}");
        
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
        {
            XTrace.WriteLineSafe("JWT授权失败：HttpContext为空");
            return;
        }
        
        XTrace.WriteLineSafe($"JWT授权处理请求：{httpContext.Request.Method} {httpContext.Request.Path}");
        
        // 未登录而被拒绝
        var result = httpContext.Request.Headers.TryGetValue("Authorization", out var authorizationHeader);
        if (!result || String.IsNullOrWhiteSpace(authorizationHeader))
        {
            XTrace.WriteLineSafe("JWT授权失败：缺少Authorization头或值为空");
            throw new UnauthorizedAccessException("未授权，请传递Header头的Authorization参数");
        }
        
        var token = authorizationHeader.ToString().Split(' ').Last().Trim();
        XTrace.WriteLineSafe($"JWT授权提取Token：{token.Substring(0, Math.Min(20, token.Length))}...");
        
        if (!_tokenStore.ExistsToken(token))
        {
            XTrace.WriteLineSafe("JWT授权失败：Token不存在于缓存中");
            throw new UnauthorizedAccessException("未授权，无效参数");
        }
        
        if (!_tokenValidator.Validate(token, _options, requirement.ValidatePayload))
        {
            XTrace.WriteLineSafe("JWT授权失败：Token验证失败（签名、过期时间或自定义验证）");
            throw new UnauthorizedAccessException("验证失败，请查看传递的参数是否正确或是否有权限访问该地址。");
        }

        // 兼容旧版本：校验From字段
        var payload = GetPayload(token);
        var endpoint = httpContext.GetEndpoint();
        var fromAttribute = endpoint?.Metadata.GetMetadata<JwtAuthorizeAttribute>();
        var requiredFrom = fromAttribute?.From;
        payload.TryGetValue("From", out var tokenFrom);
        XTrace.WriteLineSafe($"JWT授权From字段验证：要求From={requiredFrom}, Token中From={tokenFrom}");
        
        if (!requiredFrom.IsNullOrWhiteSpace())
        {
            if (!String.Equals(tokenFrom, requiredFrom, StringComparison.OrdinalIgnoreCase))
            {
                XTrace.WriteLineSafe($"JWT授权失败：From字段不匹配，要求={requiredFrom}, 实际={tokenFrom}");
                throw new UnauthorizedAccessException($"Token来源不符，要求From={requiredFrom}, 实际From={tokenFrom}");
            }
        }

        if (_options.SingleDeviceEnabled)
        {
            XTrace.WriteLineSafe("JWT授权检查单设备登录限制");
            var bindDeviceInfo = _tokenStore.GetUserDeviceToken(payload["sub"], payload["clientType"]);
            if (bindDeviceInfo?.DeviceId != payload["clientId"])
            {
                XTrace.WriteLineSafe($"JWT授权失败：设备冲突，当前设备={payload["clientId"]}, 绑定设备={bindDeviceInfo?.DeviceId}");
                throw new UnauthorizedAccessException("该账号已在其它设备登录");
            }
        }
        
        var isAuthenticated = httpContext.User.Identity.IsAuthenticated;
        XTrace.WriteLineSafe($"JWT授权用户认证状态：{isAuthenticated}");
        
        if (!isAuthenticated)
            return;
            
        XTrace.WriteLineSafe("JWT授权成功");
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
        {
            XTrace.WriteLineSafe("JWT授权失败：HttpContext为空");
            return;
        }

        XTrace.WriteLineSafe($"JWT授权处理请求：{httpContext.Request.Method} {httpContext.Request.Path}");

        // 未登录而被拒绝
        var result = httpContext.Request.Headers.TryGetValue("Authorization", out var authorizationHeader);

        if (!result || String.IsNullOrWhiteSpace(authorizationHeader))
        {
            XTrace.WriteLineSafe("JWT授权失败：缺少Authorization头或值为空");
            context.Fail();
            return;
        }

        var token = authorizationHeader.ToString().Split(' ').Last().Trim();
        XTrace.WriteLineSafe($"JWT授权提取Token：{token.Substring(0, Math.Min(20, token.Length))}...");
        
        if (!_tokenStore.ExistsToken(token))
        {
            XTrace.WriteLineSafe("JWT授权失败：Token不存在于缓存中");
            context.Fail();
            return;
        }

        if (!_tokenValidator.Validate(token, _options, requirement.ValidatePayload))
        {
            XTrace.WriteLineSafe("JWT授权失败：Token验证失败（签名、过期时间或自定义验证）");
            context.Fail();
            return;
        }

        // 登录超时
        var accessToken = _tokenStore.GetToken(token);
        if (accessToken?.IsExpired() == true)
        {
            XTrace.WriteLineSafe("JWT授权失败：Token已过期");
            context.Fail();
            return;
        }

        var payload = GetPayload(token);

        // 兼容旧版本：校验From字段
        var endpoint = httpContext.GetEndpoint();
        var fromAttribute = endpoint?.Metadata.GetMetadata<JwtAuthorizeAttribute>();
        var requiredFrom = fromAttribute?.From;
        payload.TryGetValue("From", out var tokenFrom);
        XTrace.WriteLineSafe($"JWT授权From字段验证：要求From={requiredFrom}, Token中From={tokenFrom}");
        
        if (!requiredFrom.IsNullOrWhiteSpace())
        {
            if (!String.Equals(tokenFrom, requiredFrom, StringComparison.OrdinalIgnoreCase))
            {
                XTrace.WriteLineSafe($"JWT授权失败：From字段不匹配，要求={requiredFrom}, 实际={tokenFrom}");
                context.Fail();
                return;
            }
        }

        // 单设备登录
        if (_options.SingleDeviceEnabled)
        {
            XTrace.WriteLineSafe("JWT授权检查单设备登录限制");
            var bindDeviceInfo = _tokenStore.GetUserDeviceToken(payload["sub"], payload["clientType"]);
            if (bindDeviceInfo?.DeviceId != payload["clientId"])
            {
                XTrace.WriteLineSafe($"JWT授权失败：设备冲突，当前设备={payload["clientId"]}, 绑定设备={bindDeviceInfo?.DeviceId}");
                context.Fail();
                return;
            }
        }

        var isAuthenticated = httpContext.User.Identity.IsAuthenticated;
        XTrace.WriteLineSafe($"JWT授权用户认证状态：{isAuthenticated}");
        
        if (!isAuthenticated)
            return;

        httpContext.Items["clientId"] = payload["clientId"];

        XTrace.WriteLineSafe("JWT授权成功");
        context.Succeed(requirement);
    }

    /// <summary>
    /// 获取Payload
    /// </summary>
    /// <param name="encodeJwt">加密后的Jwt令牌</param>
    private IDictionary<String, String> GetPayload(String encodeJwt)
    {
        var jwtArray = encodeJwt.Split('.');
        if (jwtArray.Length < 3)
        {
            XTrace.WriteLineSafe($"JWT授权失败：Token格式错误，分段数量={jwtArray.Length}");
            throw new ArgumentException($"非有效Jwt令牌");
        }
        var payload = JsonHelper.ToJsonEntity<Dictionary<String, String>>(Base64UrlEncoder.Decode(jwtArray[1]));
        XTrace.WriteLineSafe($"JWT授权解析Payload成功，包含字段：{string.Join(", ", payload.Keys)}");
        return payload;
    }
}
