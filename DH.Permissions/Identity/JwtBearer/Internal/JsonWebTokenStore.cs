using Microsoft.Extensions.Options;

using NewLife;
using NewLife.Caching;

using Pek.Security;

namespace DH.Permissions.Identity.JwtBearer.Internal;

/// <summary>
/// Jwt令牌存储器
/// </summary>
internal sealed class JsonWebTokenStore : IJsonWebTokenStore
{
    /// <summary>
    /// 缓存
    /// </summary>
    private readonly ICache _cache;

    /// <summary>
    /// JWT选项配置
    /// </summary>
    private readonly IOptions<JwtOptions> _jwtOptions;

    /// <summary>
    /// JWT验证器
    /// </summary>
    private readonly IJsonWebTokenValidator _validator;

    /// <summary>
    /// 初始化一个<see cref="JsonWebTokenStore"/>类型的实例
    /// </summary>
    /// <param name="cache">缓存</param>
    /// <param name="jwtOptions">JWT选项配置</param>
    /// <param name="validator">JWT验证器</param>
    public JsonWebTokenStore(ICache cache, IOptions<JwtOptions> jwtOptions, IJsonWebTokenValidator validator)
    {
        _cache = Pek.Webs.HttpContext.Current.RequestServices.GetRequiredService<ICacheProvider>().Cache;
        _cache ??= cache;
        _jwtOptions = jwtOptions;
        _validator = validator;
    }

    /// <summary>
    /// 获取刷新令牌
    /// </summary>
    /// <param name="token">刷新令牌</param>
    public RefreshToken GetRefreshToken(String token) =>
        _cache.Get<RefreshToken>(GetRefreshTokenKey(token));

    /// <summary>
    /// 保存刷新令牌
    /// </summary>
    /// <param name="token">刷新令牌</param>
    public void SaveRefreshToken(RefreshToken token) => _cache.Set(GetRefreshTokenKey(token.Value), token, token.EndUtcTime.Subtract(DateTime.UtcNow));

    /// <summary>
    /// 移除刷新令牌
    /// </summary>
    /// <param name="token">刷新令牌</param>
    public void RemoveRefreshToken(String token)
    {
        if (!_cache.ContainsKey(GetRefreshTokenKey(token)))
            return;
        _cache.Remove(GetRefreshTokenKey(token));
        if (!_cache.ContainsKey(GetBindRefreshTokenKey(token)))
            return;
        var accessToken = _cache.Get<JsonWebToken>(GetBindRefreshTokenKey(token));
        _cache.Remove(GetBindRefreshTokenKey(token));
        RemoveToken(accessToken.AccessToken);
    }

    /// <summary>
    /// 移除刷新令牌
    /// </summary>
    /// <param name="token">刷新令牌</param>
    /// <param name="expire">延时时间。秒</param>
    public void RemoveRefreshToken(String token, Int32 expire)
    {
        var key = GetRefreshTokenKey(token);
        var key1 = GetBindRefreshTokenKey(token);

        if (!_cache.ContainsKey(key))
            return;
        _cache.SetExpire(key, TimeSpan.FromSeconds(expire));

        if (!_cache.ContainsKey(key1))
            return;
        _cache.SetExpire(key1, TimeSpan.FromSeconds(expire));

        var accessToken = _cache.Get<JsonWebToken>(key1);
        RemoveToken(accessToken.AccessToken, expire);
    }

    /// <summary>
    /// 获取访问令牌
    /// </summary>
    /// <param name="token">访问令牌</param>
    public JsonWebToken GetToken(String token) => _cache.Get<JsonWebToken>(GetTokenKey(token));

    /// <summary>
    /// 移除访问令牌
    /// </summary>
    /// <param name="token">访问令牌</param>
    public void RemoveToken(String token)
    {
        if (!_cache.ContainsKey(GetTokenKey(token)))
            return;
        _cache.Remove(GetTokenKey(token));
    }
    
    /// <summary>
    /// 移除访问令牌
    /// </summary>
    /// <param name="token">访问令牌</param>
    /// <param name="expire">延时时间。秒</param>
    public void RemoveToken(String token, Int32 expire)
    {
        var key = GetTokenKey(token);

        if (!_cache.ContainsKey(key))
            return;

        _cache.SetExpire(key, TimeSpan.FromSeconds(expire));
    }

    /// <summary>
    /// 保存访问令牌
    /// </summary>
    /// <param name="token">令牌</param>
    /// <param name="expires">过期时间</param>
    public void SaveToken(JsonWebToken token, DateTime expires)
    {
        _cache.Set(GetTokenKey(token.AccessToken), token, expires.Subtract(DateTime.UtcNow));
        _cache.Set(GetBindRefreshTokenKey(token.RefreshToken), token, expires.Subtract(DateTime.UtcNow));
    }
    
    /// <summary>
    /// 是否存在访问令牌
    /// </summary>
    /// <param name="token">访问令牌</param>
    public Boolean ExistsToken(String token) => _cache.ContainsKey(GetTokenKey(token));
    
    /// <summary>
    /// 验证Token是否有效且存在于存储中
    /// </summary>
    /// <param name="token">访问令牌</param>
    /// <param name="options">Jwt选项配置</param>
    /// <param name="validator">Token验证器</param>
    /// <returns>Token是否有效且存在</returns>
    public Boolean IsValidAndExists(String token, JwtOptions options, IJsonWebTokenValidator validator)
    {
        if (token.IsNullOrWhiteSpace())
            return false;

        // 首先检查Token是否在存储中
        if (!ExistsToken(token))
            return false;

        // 然后验证Token的有效性（签名和过期时间）
        return validator.IsValidToken(token, options);
    }

    /// <summary>
    /// 验证Token是否有效且存在于存储中 - 使用注入的配置和验证器
    /// </summary>
    /// <param name="token">访问令牌</param>
    /// <returns>Token是否有效且存在</returns>
    public Boolean IsValidAndExists(String token) => IsValidAndExists(token, _jwtOptions.Value, _validator);

    /// <summary>
    /// 绑定用户设备令牌
    /// </summary>
    /// <param name="userId">用户标识</param>
    /// <param name="clientType">客户端类型</param>
    /// <param name="info">设备信息</param>
    /// <param name="expires">过期时间</param>
    public void BindUserDeviceToken(String userId, String clientType, DeviceTokenBindInfo info,
        DateTime expires) => _cache.Set(GetBindUserDeviceTokenKey(userId, clientType), info,
        expires.Subtract(DateTime.UtcNow));

    /// <summary>
    /// 获取用户设备令牌
    /// </summary>
    /// <param name="userId">用户标识</param>
    /// <param name="clientType">客户端类型</param>
    public DeviceTokenBindInfo GetUserDeviceToken(string userId, string clientType) =>
        _cache.Get<DeviceTokenBindInfo>(GetBindUserDeviceTokenKey(userId, clientType));

    /// <summary>
    /// 获取刷新令牌缓存键
    /// </summary>
    /// <param name="token">刷新令牌</param>
    private static String GetRefreshTokenKey(String token) => $"jwt:token:refresh:{token}";

    /// <summary>
    /// 获取访问令牌缓存键
    /// </summary>
    /// <param name="token">访问令牌</param>
    private static String GetTokenKey(String token) => $"jwt:token:access:{token}";

    /// <summary>
    /// 获取绑定刷新令牌缓存键
    /// </summary>
    /// <param name="token">刷新令牌</param>
    private static String GetBindRefreshTokenKey(String token) => $"jwt:token:bind:{token}";

    /// <summary>
    /// 获取绑定用户设备令牌缓存键
    /// </summary>
    /// <param name="userId">用户标识</param>
    /// <param name="clientType">客户端类型</param>
    private static String GetBindUserDeviceTokenKey(String userId, String clientType) =>
        $"jwt:token:bind_user:{userId}:{clientType}";
}
