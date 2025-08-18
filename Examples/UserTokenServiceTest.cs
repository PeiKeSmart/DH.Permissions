using DH.Permissions.Identity.JwtBearer;
using Microsoft.Extensions.Logging;
using Pek.Security;

namespace DH.Permissions.Examples;

/// <summary>
/// 用户Token服务测试示例
/// </summary>
public class UserTokenServiceTest
{
    private readonly IUserTokenService _userTokenService;
    private readonly IJsonWebTokenStore _tokenStore;
    private readonly IJsonWebTokenBuilder _tokenBuilder;
    private readonly ILogger<UserTokenServiceTest> _logger;

    public UserTokenServiceTest(
        IUserTokenService userTokenService,
        IJsonWebTokenStore tokenStore,
        IJsonWebTokenBuilder tokenBuilder,
        ILogger<UserTokenServiceTest> logger)
    {
        _userTokenService = userTokenService;
        _tokenStore = tokenStore;
        _tokenBuilder = tokenBuilder;
        _logger = logger;
    }

    /// <summary>
    /// 测试用户Token管理功能
    /// </summary>
    /// <param name="userId">用户ID</param>
    public void TestUserTokenManagement(string userId)
    {
        try
        {
            _logger.LogInformation("开始测试用户 {UserId} 的Token管理功能", userId);

            // 1. 获取用户当前的Token数量
            var initialTokenCount = _userTokenService.GetUserTokenCount(userId);
            _logger.LogInformation("用户 {UserId} 当前有 {TokenCount} 个Token", userId, initialTokenCount);

            // 2. 获取用户的所有Token详情
            var userTokens = _userTokenService.GetUserTokens(userId);
            _logger.LogInformation("用户 {UserId} 的Token详情:", userId);
            foreach (var token in userTokens)
            {
                _logger.LogInformation("- Token Hash: {TokenHash}, 客户端类型: {ClientType}, 设备ID: {DeviceId}, 过期时间: {ExpireTime}, 是否过期: {IsExpired}",
                    token.AccessTokenHash, token.ClientType, token.DeviceId, token.AccessTokenExpires, token.IsExpired);
            }

            // 3. 测试根据Token查找用户
            if (userTokens.Any())
            {
                var firstToken = userTokens.First();
                var foundUserId = _userTokenService.GetUserIdByToken(firstToken.AccessToken);
                _logger.LogInformation("根据Token查找到的用户ID: {FoundUserId}", foundUserId);
            }

            // 4. 测试撤销单个Token（如果有多个Token）
            if (userTokens.Count() > 1)
            {
                var tokenToRevoke = userTokens.First();
                _logger.LogInformation("撤销Token: {TokenHash}", tokenToRevoke.AccessTokenHash);
                _userTokenService.RevokeUserToken(userId, tokenToRevoke.AccessToken);

                // 验证撤销后的Token数量
                var afterRevokeCount = _userTokenService.GetUserTokenCount(userId);
                _logger.LogInformation("撤销后用户 {UserId} 还有 {TokenCount} 个Token", userId, afterRevokeCount);
            }

            // 5. 测试强制用户下线（如果还有Token）
            var finalTokenCount = _userTokenService.GetUserTokenCount(userId);
            if (finalTokenCount > 0)
            {
                _logger.LogInformation("强制用户 {UserId} 下线", userId);
                _userTokenService.ForceUserOffline(userId);

                // 验证下线后的Token数量
                var afterOfflineCount = _userTokenService.GetUserTokenCount(userId);
                _logger.LogInformation("强制下线后用户 {UserId} 还有 {TokenCount} 个Token", userId, afterOfflineCount);
            }

            _logger.LogInformation("用户 {UserId} 的Token管理功能测试完成", userId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "测试用户 {UserId} 的Token管理功能时发生错误", userId);
        }
    }

    /// <summary>
    /// 测试批量用户Token统计
    /// </summary>
    /// <param name="userIds">用户ID列表</param>
    public void TestBatchUserTokenStatistics(string[] userIds)
    {
        try
        {
            _logger.LogInformation("开始测试批量用户Token统计");

            var statistics = userIds.Select(userId => new
            {
                UserId = userId,
                TokenCount = _userTokenService.GetUserTokenCount(userId),
                HasActiveTokens = _userTokenService.GetUserTokenCount(userId) > 0
            }).ToList();

            var totalUsers = userIds.Length;
            var onlineUsers = statistics.Count(s => s.HasActiveTokens);

            _logger.LogInformation("统计结果: 总用户数 {TotalUsers}, 在线用户数 {OnlineUsers}", totalUsers, onlineUsers);

            foreach (var stat in statistics)
            {
                _logger.LogInformation("用户 {UserId}: {TokenCount} 个Token, 在线状态: {IsOnline}",
                    stat.UserId, stat.TokenCount, stat.HasActiveTokens ? "是" : "否");
            }

            _logger.LogInformation("批量用户Token统计测试完成");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "测试批量用户Token统计时发生错误");
        }
    }
}
