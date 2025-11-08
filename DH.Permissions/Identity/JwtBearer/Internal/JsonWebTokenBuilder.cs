using System.IdentityModel.Tokens.Jwt;
using System.Text;

using DH.Permissions.Security;

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

using NewLife;
using NewLife.Log;
using NewLife.Serialization;

using Pek;
using Pek.Configs;
using Pek.Exceptions;
using Pek.Helpers;
using Pek.Security;
using Pek.Timing;
using Pek.Webs;

namespace DH.Permissions.Identity.JwtBearer.Internal;

/// <summary>
/// Jwt构建器
/// </summary>
internal sealed class JsonWebTokenBuilder : IJsonWebTokenBuilder
{
    /// <summary>
    /// Jwt令牌存储器
    /// </summary>
    private readonly IJsonWebTokenStore _tokenStore;

    /// <summary>
    /// 令牌Payload存储器
    /// </summary>
    private readonly ITokenPayloadStore _tokenPayloadStore;

    /// <summary>
    /// Jwt安全令牌处理器
    /// </summary>
    private readonly JwtSecurityTokenHandler _tokenHandler;

    /// <summary>
    /// Jwt选项配置
    /// </summary>
    private readonly JwtOptions _options;

    /// <summary>
    /// HTTP上下文访问器
    /// </summary>
    private readonly IHttpContextAccessor _httpContextAccessor;

    /// <summary>
    /// 初始化一个<see cref="JsonWebTokenBuilder"/>类型的实例
    /// </summary>
    /// <param name="tokenStore">Jwt令牌存储器</param>
    /// <param name="tokenPayloadStore">令牌Payload存储器</param>
    /// <param name="options">Jwt选项配置</param>
    /// <param name="httpContextAccessor">HTTP上下文访问器</param>
    public JsonWebTokenBuilder(IJsonWebTokenStore tokenStore
        , ITokenPayloadStore tokenPayloadStore
        , IOptions<JwtOptions> options
        , IHttpContextAccessor httpContextAccessor)
    {
        _tokenStore = tokenStore;
        _tokenPayloadStore = tokenPayloadStore;
        _options = options.Value;
        _httpContextAccessor = httpContextAccessor;
        if (_tokenHandler == null)
            _tokenHandler = new JwtSecurityTokenHandler();
    }

    /// <summary>
    /// 创建令牌
    /// </summary>
    /// <param name="payload">负载</param>
    public JsonWebToken Create(IDictionary<String, String> payload) => Create(payload, _options);

    /// <summary>
    /// 创建令牌
    /// </summary>
    /// <param name="payload">负载</param>
    /// <param name="AccessExpireMinutes">访问令牌有效期分钟数</param>
    /// <param name="RefreshExpireMinutes">刷新令牌有效期分钟数</param>
    public JsonWebToken Create(IDictionary<String, String> payload, Double RefreshExpireMinutes, Double AccessExpireMinutes = 0)
    {
        var options = _options.DeepCloneWithJson();

        if (AccessExpireMinutes > 0)
        {
            options.AccessExpireMinutes = AccessExpireMinutes;
        }

        if (RefreshExpireMinutes > 0)
        {
            options.RefreshExpireMinutes = RefreshExpireMinutes;
        }

        return Create(payload, options);
    }

    /// <summary>
    /// 创建令牌
    /// </summary>
    /// <param name="payload">负载</param>
    /// <param name="options">Jwt选项配置</param>
    public JsonWebToken Create(IDictionary<String, String> payload, JwtOptions options)
    {
        if (options.Secret.IsNullOrWhiteSpace())
            throw new ArgumentNullException(nameof(options.Secret),
                $@"{nameof(options.Secret)}为Null或空字符串。请在""appsettings.json""配置""{nameof(JwtOptions)}""节点及其子节点""{nameof(JwtOptions.Secret)}""");

        XTrace.WriteLine($"获取到的负载：{payload.ToJson()}");

        // 获取真实设备ID
        var httpContext = _httpContextAccessor.HttpContext;
        var realDeviceId = httpContext != null ? DHWebHelper.FillDeviceId(httpContext) : Guid.NewGuid().ToString();

        // 获取用户ID（提前获取，避免重复声明）
        var userId = GetUserId(payload);
        if (userId.IsEmpty()) throw new ArgumentException("不存在用户标识");

        // 验证clientId与真实设备ID的一致性
        var clientId = payload.TryGetValue("clientId", out var ClientId) ? ClientId : realDeviceId;

        // 检查是否允许跨设备使用Token（测试环境开关）
        var allowCrossDevice = PekSysSetting.Current.AllowJwtCrossDevice;

        if (httpContext != null && clientId != realDeviceId && !allowCrossDevice)
        {
            SecurityLogger.LogDeviceIdMismatch(httpContext, clientId, realDeviceId, userId, "JsonWebTokenBuilder_Create", new { Action = "TokenCreation" });
            if (!SecuritySetting.Current.AllowCrossDevice)
                throw new UnauthorizedAccessException("设备标识不匹配，疑似非法请求");
        }
        else if (httpContext != null && clientId != realDeviceId && allowCrossDevice)
        {
            XTrace.WriteLine($"[开发模式] 允许跨设备Token创建: clientId={clientId}, realDeviceId={realDeviceId}, userId={userId}");
        }

        // 确保使用真实设备ID作为clientId
        clientId = realDeviceId;
        var clientType = payload.TryGetValue("clientType", out var ClientType) ? ClientType : "admin";

        if (!payload.TryGetValue("From", out var From)) throw new ArgumentException("不包含来源标识");

        var claims = Helper.ToClaims(payload);

        // 生成刷新令牌
        var (refreshToken, refreshExpires) =
            Helper.CreateToken(_tokenHandler, claims, options, JsonWebTokenType.RefreshToken);
        var refreshTokenStr = refreshToken;
        _tokenStore.SaveRefreshToken(new RefreshToken()
        {
            ClientId = clientId,
            EndUtcTime = refreshExpires,
            Value = refreshTokenStr
        });

        // 生成访问令牌
        var (token, accessExpires) =
            Helper.CreateToken(_tokenHandler, claims, options, JsonWebTokenType.AccessToken);
        var accessToken = new JsonWebToken()
        {
            AccessToken = token,
            AccessTokenUtcExpires = Conv.CTo<Int64>(accessExpires.ToJsGetTime()),
            RefreshToken = refreshTokenStr,
            RefreshUtcExpires = Conv.CTo<Int64>(refreshExpires.ToJsGetTime())
        };
        _tokenStore.SaveToken(accessToken, accessExpires);

        // 绑定用户设备令牌
        _tokenStore.BindUserDeviceToken(userId, clientType, new DeviceTokenBindInfo()
        {
            UserId = userId,
            DeviceId = clientId,
            DeviceType = clientType,
            Token = accessToken,
        }, refreshExpires);
        // 存储payload
        _tokenPayloadStore.Save(refreshToken, payload, refreshExpires);
        _tokenPayloadStore.Save(token, payload, accessExpires);
        return accessToken;
    }

    /// <summary>
    /// 获取用户标识
    /// </summary>
    /// <param name="payload">负载列表</param>
    private String GetUserId(IDictionary<String, String> payload)
    {
        var userId = payload.GetOrDefault(IdentityModel.JwtClaimTypes.Subject, String.Empty);
        if (userId.IsEmpty())
            userId = payload.GetOrDefault(System.Security.Claims.ClaimTypes.Sid, String.Empty);
        return userId;
    }

    /// <summary>
    /// 刷新令牌
    /// </summary>
    /// <param name="refreshToken">刷新令牌</param>
    /// <returns>刷新成功返回新令牌,失败抛出JwtRefreshException异常(ErrCode=9994)</returns>
    public JsonWebToken Refresh(String refreshToken) => Refresh(refreshToken, _options);

    /// <summary>
    /// 刷新令牌
    /// </summary>
    /// <param name="refreshToken">刷新令牌</param>
    /// <param name="RefreshExpireMinutes">刷新令牌有效期分钟数</param>
    /// <returns>刷新成功返回新令牌,失败抛出JwtRefreshException异常(ErrCode=9994)</returns>
    public JsonWebToken Refresh(String refreshToken, Double RefreshExpireMinutes)
    {
        var options = _options.DeepCloneWithJson();

        if (RefreshExpireMinutes > 0)
        {
            options.RefreshExpireMinutes = RefreshExpireMinutes;
        }

        return Refresh(refreshToken, _options);
    }

    /// <summary>
    /// 刷新令牌
    /// </summary>
    /// <param name="refreshToken">刷新令牌</param>
    /// <param name="options"></param>
    /// <returns>刷新成功返回新令牌,失败抛出JwtRefreshException异常(ErrCode=9994)</returns>
    public JsonWebToken Refresh(String refreshToken, JwtOptions options)
    {
        if (String.IsNullOrWhiteSpace(refreshToken))
            throw new JwtRefreshException("刷新令牌不存在或已过期", 9994);
            
        var parameters = new TokenValidationParameters()
        {
            ValidIssuer = options.Issuer,
            ValidAudience = options.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(options.Secret)),
        };
        var tokenModel = _tokenStore.GetRefreshToken(refreshToken);
        if (tokenModel == null || tokenModel.Value != refreshToken || tokenModel.EndUtcTime <= DateTime.UtcNow)
        {
            if (tokenModel != null && tokenModel.EndUtcTime <= DateTime.UtcNow)
            {
                _tokenStore.RemoveRefreshToken(refreshToken);
                _tokenPayloadStore.Remove(refreshToken);
            }

            throw new JwtRefreshException("刷新令牌不存在或已过期", 9994);
        }

        var principal = _tokenHandler.ValidateToken(refreshToken, parameters, out var securityToken);
        var payload = _tokenPayloadStore.Get(refreshToken);
        var result = Create(payload, options);
        if (result != null)
        {
            _tokenStore.RemoveRefreshToken(refreshToken);
            _tokenPayloadStore.Remove(refreshToken);
        }
        return result;
    }

    /// <summary>
    /// 刷新令牌，延时清理数据
    /// </summary>
    /// <param name="refreshToken">刷新令牌</param>
    /// <param name="expire">延时时间。秒</param>
    /// <returns>刷新成功返回新令牌,失败抛出JwtRefreshException异常(ErrCode=9994)</returns>
    public JsonWebToken Refresh(String refreshToken, Int32 expire) => Refresh(refreshToken, expire, _options);

    /// <summary>
    /// 刷新令牌，延时清理数据
    /// </summary>
    /// <param name="refreshToken">刷新令牌</param>
    /// <param name="expire">延时时间。秒</param>
    /// <param name="RefreshExpireMinutes">刷新令牌有效期分钟数</param>
    /// <returns>刷新成功返回新令牌,失败抛出JwtRefreshException异常(ErrCode=9994)</returns>
    public JsonWebToken Refresh(String refreshToken, Int32 expire, Double RefreshExpireMinutes)
    {
        var options = _options.DeepCloneWithJson();

        if (RefreshExpireMinutes > 0)
        {
            options.RefreshExpireMinutes = RefreshExpireMinutes;
        }

        return Refresh(refreshToken, expire, _options);
    }

    /// <summary>
    /// 刷新令牌，延时清理数据
    /// </summary>
    /// <param name="refreshToken">刷新令牌</param>
    /// <param name="expire">延时时间。秒</param>
    /// <param name="options"></param>
    /// <returns>刷新成功返回新令牌,失败抛出JwtRefreshException异常(ErrCode=9994)</returns>
    public JsonWebToken Refresh(String refreshToken, Int32 expire, JwtOptions options)
    {
        if (string.IsNullOrWhiteSpace(refreshToken))
            throw new JwtRefreshException("刷新令牌不存在或已过期", 9994);
            
        var parameters = new TokenValidationParameters()
        {
            ValidIssuer = _options.Issuer,
            ValidAudience = _options.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.Secret)),
        };
        var tokenModel = _tokenStore.GetRefreshToken(refreshToken);
        if (tokenModel == null || tokenModel.Value != refreshToken || tokenModel.EndUtcTime <= DateTime.UtcNow)
        {
            if (tokenModel != null && tokenModel.EndUtcTime <= DateTime.UtcNow)
            {
                _tokenStore.RemoveRefreshToken(refreshToken);
                _tokenPayloadStore.Remove(refreshToken);
            }

            throw new JwtRefreshException("刷新令牌不存在或已过期", 9994);
        }

        var principal = _tokenHandler.ValidateToken(refreshToken, parameters, out var securityToken);
        var payload = _tokenPayloadStore.Get(refreshToken);
        var result = Create(payload, _options);
        if (result != null)
        {
            _tokenStore.RemoveRefreshToken(refreshToken, expire);
            _tokenPayloadStore.Remove(refreshToken, expire);
        }
        return result;
    }
}
