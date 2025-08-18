using DH.Permissions.Identity.JwtBearer;
using DH.Permissions.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Pek.Configs;
using Pek.Helpers;
using Pek.Security;

namespace DH.Permissions.Examples;

/// <summary>
/// 设备ID验证功能测试示例
/// </summary>
public class DeviceIdValidationTest
{
    private readonly IJsonWebTokenBuilder _tokenBuilder;
    private readonly IJsonWebTokenStore _tokenStore;
    private readonly IJsonWebTokenValidator _tokenValidator;
    private readonly ILogger<DeviceIdValidationTest> _logger;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public DeviceIdValidationTest(
        IJsonWebTokenBuilder tokenBuilder,
        IJsonWebTokenStore tokenStore,
        IJsonWebTokenValidator tokenValidator,
        ILogger<DeviceIdValidationTest> logger,
        IHttpContextAccessor httpContextAccessor)
    {
        _tokenBuilder = tokenBuilder;
        _tokenStore = tokenStore;
        _tokenValidator = tokenValidator;
        _logger = logger;
        _httpContextAccessor = httpContextAccessor;
    }

    /// <summary>
    /// 测试设备ID验证功能
    /// </summary>
    /// <param name="userId">用户ID</param>
    /// <param name="clientType">客户端类型</param>
    public void TestDeviceIdValidation(string userId, string clientType = "web")
    {
        try
        {
            _logger.LogInformation("开始测试设备ID验证功能");

            // 1. 获取当前设备ID
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext == null)
            {
                _logger.LogWarning("HttpContext为空，无法进行设备ID验证测试");
                return;
            }

            var currentDeviceId = DHWebHelper.FillDeviceId(httpContext);
            _logger.LogInformation("当前设备ID: {DeviceId}", currentDeviceId);

            // 2. 测试正常Token创建（使用正确的设备ID）
            var normalPayload = new Dictionary<string, string>
            {
                ["sub"] = userId,
                ["clientId"] = currentDeviceId,
                ["clientType"] = clientType,
                ["From"] = "TestApp"
            };

            _logger.LogInformation("测试正常Token创建...");
            var normalToken = _tokenBuilder.Create(normalPayload);
            _logger.LogInformation("✅ 正常Token创建成功: {TokenHash}", normalToken.AccessToken.GetHashCode().ToString("X8"));

            // 3. 测试跨设备Token创建（使用不同的设备ID）
            var crossDevicePayload = new Dictionary<string, string>
            {
                ["sub"] = userId,
                ["clientId"] = "different-device-id",
                ["clientType"] = clientType,
                ["From"] = "TestApp"
            };

            // 获取当前跨设备设置
            var originalAllowCrossDevice = PekSysSetting.Current.AllowJwtCrossDevice;
            _logger.LogInformation("当前跨设备设置: {AllowCrossDevice}", originalAllowCrossDevice);

            if (!originalAllowCrossDevice)
            {
                _logger.LogInformation("测试跨设备Token创建（应该失败）...");
                try
                {
                    var crossDeviceToken = _tokenBuilder.Create(crossDevicePayload);
                    _logger.LogWarning("⚠️ 跨设备Token创建应该失败但成功了");
                }
                catch (UnauthorizedAccessException ex)
                {
                    _logger.LogInformation("✅ 跨设备Token创建正确失败: {Message}", ex.Message);
                }
            }
            else
            {
                _logger.LogInformation("测试跨设备Token创建（开发模式，应该成功）...");
                var crossDeviceToken = _tokenBuilder.Create(crossDevicePayload);
                _logger.LogInformation("✅ 跨设备Token创建成功（开发模式）: {TokenHash}", crossDeviceToken.AccessToken.GetHashCode().ToString("X8"));
            }

            // 4. 测试Token验证
            _logger.LogInformation("测试Token验证...");
            var isValid = _tokenStore.ExistsToken(normalToken.AccessToken);
            _logger.LogInformation("Token存在性验证: {IsValid}", isValid);

            // 5. 显示安全日志记录功能
            _logger.LogInformation("测试安全日志记录...");
            SecurityLogger.LogTokenCreated(httpContext, userId, currentDeviceId, clientType);
            SecurityLogger.LogTokenValidated(httpContext, userId, currentDeviceId);

            _logger.LogInformation("设备ID验证功能测试完成");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "设备ID验证功能测试失败");
            throw;
        }
    }

    /// <summary>
    /// 测试跨设备开关功能
    /// </summary>
    /// <param name="userId">用户ID</param>
    public void TestCrossDeviceSwitch(string userId)
    {
        try
        {
            _logger.LogInformation("开始测试跨设备开关功能");

            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext == null)
            {
                _logger.LogWarning("HttpContext为空，无法进行跨设备开关测试");
                return;
            }

            var currentDeviceId = DHWebHelper.FillDeviceId(httpContext);
            var differentDeviceId = "test-different-device-" + Guid.NewGuid().ToString("N")[..8];

            var payload = new Dictionary<string, string>
            {
                ["sub"] = userId,
                ["clientId"] = differentDeviceId,
                ["clientType"] = "web",
                ["From"] = "TestApp"
            };

            // 记录原始设置
            var originalSetting = PekSysSetting.Current.AllowJwtCrossDevice;
            _logger.LogInformation("原始跨设备设置: {OriginalSetting}", originalSetting);

            // 测试禁用跨设备时的行为
            _logger.LogInformation("测试禁用跨设备时的Token创建...");
            PekSysSetting.Current.AllowJwtCrossDevice = false;
            
            try
            {
                var token1 = _tokenBuilder.Create(payload);
                _logger.LogWarning("⚠️ 禁用跨设备时Token创建应该失败但成功了");
            }
            catch (UnauthorizedAccessException)
            {
                _logger.LogInformation("✅ 禁用跨设备时Token创建正确失败");
            }

            // 测试启用跨设备时的行为
            _logger.LogInformation("测试启用跨设备时的Token创建...");
            PekSysSetting.Current.AllowJwtCrossDevice = true;
            
            try
            {
                var token2 = _tokenBuilder.Create(payload);
                _logger.LogInformation("✅ 启用跨设备时Token创建成功: {TokenHash}", token2.AccessToken.GetHashCode().ToString("X8"));
            }
            catch (Exception ex)
            {
                _logger.LogError("❌ 启用跨设备时Token创建失败: {Message}", ex.Message);
            }

            // 恢复原始设置
            PekSysSetting.Current.AllowJwtCrossDevice = originalSetting;
            _logger.LogInformation("已恢复原始跨设备设置: {OriginalSetting}", originalSetting);

            _logger.LogInformation("跨设备开关功能测试完成");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "跨设备开关功能测试失败");
            throw;
        }
    }

    /// <summary>
    /// 显示功能使用说明
    /// </summary>
    public void ShowUsageInstructions()
    {
        _logger.LogInformation(@"
=== DH.Permissions 设备ID验证功能使用说明 ===

1. 设备ID获取：
   - 使用 DHWebHelper.FillDeviceId(httpContext) 获取设备ID
   - 设备ID基于Cookie和Session，确保同一设备的一致性

2. 跨设备控制开关：
   - 使用 PekSysSetting.Current.AllowJwtCrossDevice 控制
   - true: 允许跨设备使用Token（测试环境）
   - false: 禁止跨设备使用Token（生产环境）

3. Token创建时验证：
   - 自动比较payload中的clientId与当前设备ID
   - 不匹配且禁止跨设备时抛出UnauthorizedAccessException

4. Token验证时检查：
   - 在JsonWebTokenAuthorizationHandler中自动验证
   - 支持ThrowException和ResultHandle两种模式

5. 安全日志记录：
   - SecurityLogger.LogDeviceIdMismatch() 记录设备不匹配事件
   - SecurityLogger.LogTokenCreated() 记录Token创建事件
   - SecurityLogger.LogTokenValidated() 记录Token验证事件

6. 配置建议：
   - 开发/测试环境：AllowJwtCrossDevice = true
   - 生产环境：AllowJwtCrossDevice = false
");
    }
}
