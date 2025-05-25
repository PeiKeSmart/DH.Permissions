using Pek.Security;

namespace DH.Permissions.Identity.JwtBearer;

/// <summary>
/// Jwt令牌校验器
/// </summary>
public interface IJsonWebTokenValidator
{
    /// <summary>
    /// 校验
    /// </summary>
    /// <param name="encodeJwt">加密后的Jwt令牌</param>
    /// <param name="options">Jwt选项配置</param>
    /// <param name="validatePayload">校验负载</param>
    bool Validate(string encodeJwt, JwtOptions options,
        Func<IDictionary<string, string>, JwtOptions, bool> validatePayload);
    
    /// <summary>
    /// 简单校验Token有效性（只验证签名和过期时间）
    /// </summary>
    /// <param name="encodeJwt">加密后的Jwt令牌</param>
    /// <param name="options">Jwt选项配置</param>
    /// <returns>Token是否有效</returns>
    bool IsValidToken(string encodeJwt, JwtOptions options);

    /// <summary>
    /// 简单校验Token有效性（只验证签名和过期时间）- 使用注入的配置
    /// </summary>
    /// <param name="encodeJwt">加密后的Jwt令牌</param>
    /// <returns>Token是否有效</returns>
    bool IsValidToken(string encodeJwt);
}
