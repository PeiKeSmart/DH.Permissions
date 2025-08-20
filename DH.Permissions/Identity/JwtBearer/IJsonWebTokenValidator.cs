using Pek.Security;

namespace DH.Permissions.Identity.JwtBearer;

/// <summary>
/// Token验证结果
/// </summary>
public class TokenValidationResult
{
    /// <summary>
    /// 是否验证成功
    /// </summary>
    public Boolean IsValid { get; set; }

    /// <summary>
    /// Token的Payload内容
    /// </summary>
    public IDictionary<String, String> Payload { get; set; }

    /// <summary>
    /// Token的Header内容
    /// </summary>
    public IDictionary<String, String> Header { get; set; }

    /// <summary>
    /// 错误信息
    /// </summary>
    public String ErrorMessage { get; set; }

    /// <summary>
    /// 原始Token字符串
    /// </summary>
    public String Token { get; set; }

    /// <summary>
    /// 验证时间戳
    /// </summary>
    public DateTime ValidatedAt { get; set; }

    /// <summary>
    /// 创建成功的验证结果
    /// </summary>
    public static TokenValidationResult Success(String token, IDictionary<String, String> payload, IDictionary<String, String> header = null)
    {
        return new TokenValidationResult
        {
            IsValid = true,
            Token = token,
            Payload = payload,
            Header = header,
            ValidatedAt = DateTime.UtcNow
        };
    }

    /// <summary>
    /// 创建失败的验证结果
    /// </summary>
    public static TokenValidationResult Failure(String token, String errorMessage)
    {
        return new TokenValidationResult
        {
            IsValid = false,
            Token = token,
            ErrorMessage = errorMessage,
            ValidatedAt = DateTime.UtcNow
        };
    }
}

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
    Boolean Validate(String encodeJwt, JwtOptions options,
        Func<IDictionary<String, String>, JwtOptions, Boolean> validatePayload);

    /// <summary>
    /// 校验并返回详细结果（包含解析的payload）
    /// </summary>
    /// <param name="encodeJwt">加密后的Jwt令牌</param>
    /// <param name="options">Jwt选项配置</param>
    /// <param name="validatePayload">校验负载</param>
    /// <returns>包含验证结果和解析数据的对象</returns>
    TokenValidationResult ValidateWithResult(String encodeJwt, JwtOptions options,
        Func<IDictionary<String, String>, JwtOptions, Boolean> validatePayload);

    /// <summary>
    /// 简单校验Token有效性（只验证签名和过期时间）
    /// </summary>
    /// <param name="encodeJwt">加密后的Jwt令牌</param>
    /// <param name="options">Jwt选项配置</param>
    /// <returns>Token是否有效</returns>
    Boolean IsValidToken(String encodeJwt, JwtOptions options);

    /// <summary>
    /// 简单校验Token有效性（只验证签名和过期时间）- 使用注入的配置
    /// </summary>
    /// <param name="encodeJwt">加密后的Jwt令牌</param>
    /// <returns>Token是否有效</returns>
    Boolean IsValidToken(String encodeJwt);

    /// <summary>
    /// 简单校验Token有效性并返回详细结果
    /// </summary>
    /// <param name="encodeJwt">加密后的Jwt令牌</param>
    /// <param name="options">Jwt选项配置</param>
    /// <returns>包含验证结果和解析数据的对象</returns>
    TokenValidationResult IsValidTokenWithResult(String encodeJwt, JwtOptions options);

    /// <summary>
    /// 简单校验Token有效性并返回详细结果 - 使用注入的配置
    /// </summary>
    /// <param name="encodeJwt">加密后的Jwt令牌</param>
    /// <returns>包含验证结果和解析数据的对象</returns>
    TokenValidationResult IsValidTokenWithResult(String encodeJwt);
}
