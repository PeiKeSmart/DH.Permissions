using DH.Permissions.Identity.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Pek.Models;

namespace DH.Permissions.Examples;

/// <summary>
/// 令牌刷新控制器示例
/// </summary>
/// <remarks>
/// 展示如何在控制器中捕获JwtRefreshException并返回DGResult(ErrCode=9994)
/// </remarks>
public class TokenRefreshControllerExample : ControllerBase
{
    private readonly IJsonWebTokenBuilder _jwtBuilder;

    public TokenRefreshControllerExample(IJsonWebTokenBuilder jwtBuilder)
    {
        _jwtBuilder = jwtBuilder;
    }

    /// <summary>
    /// 刷新令牌示例
    /// </summary>
    /// <param name="RefreshToken">刷新令牌</param>
    /// <param name="AId">应用ID(可选)</param>
    /// <returns>DGResult包含新令牌或错误信息(ErrCode=9994)</returns>
    [HttpPost("api/token/refresh")]
    public IActionResult RefreshToken(String RefreshToken, Int32? AId = null)
    {
        try
        {
            // 调用刷新方法,延时60秒清理数据
            var result = _jwtBuilder.Refresh(RefreshToken, 60);

            // 刷新成功,返回新令牌
            return new DGResult<JsonWebToken>
            {
                Code = StateCode.Ok,
                Data = result,
                Message = "刷新成功"
            };
        }
        catch (JwtRefreshException ex)
        {
            // 捕获JWT刷新异常,使用其中的ErrCode(9994)
            return new DGResult
            {
                Code = StateCode.Fail,
                ErrCode = ex.ErrCode,  // 9994 - 刷新令牌不存在或已过期
                Message = ex.Message
            };
        }
        catch (Exception ex)
        {
            // 其他异常,使用通用错误码
            return new DGResult
            {
                Code = StateCode.Fail,
                ErrCode = 500,
                Message = $"系统错误: {ex.Message}"
            };
        }
    }
}
