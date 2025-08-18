using Microsoft.Extensions.Logging;
using Pek.Security;

namespace DH.Permissions.Identity.JwtBearer.Internal;

/// <summary>
/// 用户Token管理服务实现
/// </summary>
internal sealed class UserTokenService : IUserTokenService
{
    private readonly IJsonWebTokenStore _tokenStore;
    private readonly ILogger<UserTokenService> _logger;

    /// <summary>
    /// 初始化一个<see cref="UserTokenService"/>类型的实例
    /// </summary>
    /// <param name="tokenStore">Token存储器</param>
    /// <param name="logger">日志记录器</param>
    public UserTokenService(IJsonWebTokenStore tokenStore, ILogger<UserTokenService> logger)
    {
        _tokenStore = tokenStore;
        _logger = logger;
    }

    /// <summary>
    /// 获取用户的所有活跃Token
    /// </summary>
    /// <param name="userId">用户标识</param>
    public IEnumerable<UserTokenInfo> GetUserTokens(String userId)
    {
        try
        {
            var accessTokens = _tokenStore.GetUserAccessTokens(userId);
            var userTokens = new List<UserTokenInfo>();

            foreach (var accessToken in accessTokens)
            {
                var jsonWebToken = _tokenStore.GetToken(accessToken);
                if (jsonWebToken != null && !IsTokenExpired(jsonWebToken))
                {
                    userTokens.Add(ConvertToUserTokenInfo(jsonWebToken, userId));
                }
            }

            return userTokens;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "获取用户 {UserId} 的Token列表时发生错误", userId);
            return Enumerable.Empty<UserTokenInfo>();
        }
    }

    /// <summary>
    /// 强制用户下线（撤销所有Token）
    /// </summary>
    /// <param name="userId">用户标识</param>
    public void ForceUserOffline(String userId)
    {
        try
        {
            _logger.LogInformation("强制用户 {UserId} 下线", userId);
            _tokenStore.RemoveAllUserTokens(userId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "强制用户 {UserId} 下线时发生错误", userId);
            throw;
        }
    }

    /// <summary>
    /// 撤销用户的指定Token
    /// </summary>
    /// <param name="userId">用户标识</param>
    /// <param name="accessToken">访问令牌</param>
    public void RevokeUserToken(String userId, String accessToken)
    {
        try
        {
            var tokenHash = accessToken.GetHashCode().ToString("X8");
            _logger.LogInformation("撤销用户 {UserId} 的Token: {TokenHash}", userId, tokenHash);
            
            // 获取对应的JsonWebToken以便清理RefreshToken
            var jsonWebToken = _tokenStore.GetToken(accessToken);
            if (jsonWebToken != null)
            {
                // 删除AccessToken
                _tokenStore.RemoveToken(accessToken);
                
                // 删除对应的RefreshToken
                if (!String.IsNullOrEmpty(jsonWebToken.RefreshToken))
                {
                    _tokenStore.RemoveRefreshToken(jsonWebToken.RefreshToken);
                }
            }
        }
        catch (Exception ex)
        {
            var tokenHash = accessToken?.GetHashCode().ToString("X8");
            _logger.LogError(ex, "撤销用户 {UserId} 的Token {TokenHash} 时发生错误", userId, tokenHash);
            throw;
        }
    }

    /// <summary>
    /// 根据Token获取用户ID
    /// </summary>
    /// <param name="accessToken">访问令牌</param>
    public String GetUserIdByToken(String accessToken)
    {
        try
        {
            var jsonWebToken = _tokenStore.GetToken(accessToken);
            return jsonWebToken?.UId.ToString();
        }
        catch (Exception ex)
        {
            var tokenHash = accessToken?.GetHashCode().ToString("X8");
            _logger.LogError(ex, "根据Token {TokenHash} 获取用户ID时发生错误", tokenHash);
            return null;
        }
    }

    /// <summary>
    /// 获取用户Token数量
    /// </summary>
    /// <param name="userId">用户标识</param>
    public Int32 GetUserTokenCount(String userId)
    {
        try
        {
            return _tokenStore.GetUserAccessTokens(userId).Count();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "获取用户 {UserId} 的Token数量时发生错误", userId);
            return 0;
        }
    }

    #region 私有方法

    /// <summary>
    /// 检查Token是否过期
    /// </summary>
    private static Boolean IsTokenExpired(JsonWebToken token)
    {
        var expireTime = DateTimeOffset.FromUnixTimeMilliseconds(token.AccessTokenUtcExpires).DateTime;
        return DateTime.UtcNow > expireTime;
    }

    /// <summary>
    /// 转换为UserTokenInfo
    /// </summary>
    private UserTokenInfo ConvertToUserTokenInfo(JsonWebToken jsonWebToken, String userId)
    {
        var userTokenInfo = new UserTokenInfo
        {
            UserId = userId,
            AccessToken = jsonWebToken.AccessToken,
            RefreshToken = jsonWebToken.RefreshToken,
            AccessTokenUtcExpires = jsonWebToken.AccessTokenUtcExpires,
            RefreshUtcExpires = jsonWebToken.RefreshUtcExpires,
            UId = jsonWebToken.UId,
            ClientType = "unknown",
            DeviceId = "unknown"
        };

        // 尝试从设备绑定信息中获取ClientType和DeviceId
        // 这里可以遍历常见的客户端类型来查找匹配的设备信息
        var commonClientTypes = new[] { "web", "mobile", "desktop", "api" };
        foreach (var clientType in commonClientTypes)
        {
            var deviceInfo = _tokenStore.GetUserDeviceToken(userId, clientType);
            if (deviceInfo?.Token?.AccessToken == jsonWebToken.AccessToken)
            {
                userTokenInfo.ClientType = clientType;
                userTokenInfo.DeviceId = deviceInfo.DeviceId ?? "unknown";
                break;
            }
        }

        return userTokenInfo;
    }

    #endregion
}
