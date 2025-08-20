using System.Security.Cryptography;
using System.Text;

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

using NewLife;
using NewLife.Serialization;

using Pek.Security;

namespace DH.Permissions.Identity.JwtBearer.Internal;

/// <summary>
/// Jwt令牌校验器
/// </summary>
internal sealed class JsonWebTokenValidator : IJsonWebTokenValidator
{
    private readonly IOptions<JwtOptions> _jwtOptions;

    /// <summary>
    /// 构造函数
    /// </summary>
    /// <param name="jwtOptions">JWT选项配置</param>
    public JsonWebTokenValidator(IOptions<JwtOptions> jwtOptions)
    {
        _jwtOptions = jwtOptions;
    }
    
    /// <summary>
    /// 校验
    /// </summary>
    /// <param name="encodeJwt">加密后的Jwt令牌</param>
    /// <param name="options">Jwt选项配置</param>
    /// <param name="validatePayload">校验负载</param>
    public Boolean Validate(String encodeJwt, JwtOptions options, Func<IDictionary<String, String>, JwtOptions, Boolean> validatePayload)
    {
        var result = ValidateWithResult(encodeJwt, options, validatePayload);
        return result.IsValid;
    }

    /// <summary>
    /// 校验并返回详细结果（包含解析的payload）
    /// </summary>
    /// <param name="encodeJwt">加密后的Jwt令牌</param>
    /// <param name="options">Jwt选项配置</param>
    /// <param name="validatePayload">校验负载</param>
    /// <returns>包含验证结果和解析数据的对象</returns>
    public TokenValidationResult ValidateWithResult(String encodeJwt, JwtOptions options, Func<IDictionary<String, String>, JwtOptions, Boolean> validatePayload)
    {
        if (options.Secret.IsNullOrWhiteSpace())
            return TokenValidationResult.Failure(encodeJwt,
                $@"{nameof(options.Secret)}为Null或空字符串。请在""appsettings.json""配置""{nameof(JwtOptions)}""节点及其子节点""{nameof(JwtOptions.Secret)}""");

        var jwtArray = encodeJwt.Split('.');
        if (jwtArray.Length < 3)
            return TokenValidationResult.Failure(encodeJwt, "Token格式无效，缺少必要的部分");

        try
        {
            var header = JsonHelper.ToJsonEntity<Dictionary<String, String>>(Base64UrlEncoder.Decode(jwtArray[0]));
            var payload = JsonHelper.ToJsonEntity<Dictionary<String, String>>(Base64UrlEncoder.Decode(jwtArray[1]));

            // 首先验证签名是否正确
            var hs256 = new HMACSHA256(Encoding.UTF8.GetBytes(options.Secret));
            var sign = Base64UrlEncoder.Encode(
                hs256.ComputeHash(Encoding.UTF8.GetBytes(String.Concat(jwtArray[0], ".", jwtArray[1]))));

            // 签名不正确直接返回
            if (!String.Equals(jwtArray[2], sign))
                return TokenValidationResult.Failure(encodeJwt, "Token签名验证失败");

            // 进行自定义验证
            if (!validatePayload(payload, options))
                return TokenValidationResult.Failure(encodeJwt, "自定义验证失败");

            return TokenValidationResult.Success(encodeJwt, payload, header);
        }
        catch (Exception ex)
        {
            return TokenValidationResult.Failure(encodeJwt, $"Token解析失败: {ex.Message}");
        }
    }
    
    /// <summary>
    /// 简单校验Token有效性（只验证签名和过期时间）
    /// </summary>
    /// <param name="encodeJwt">加密后的Jwt令牌</param>
    /// <param name="options">Jwt选项配置</param>
    /// <returns>Token是否有效</returns>
    public Boolean IsValidToken(String encodeJwt, JwtOptions options)
    {
        var result = IsValidTokenWithResult(encodeJwt, options);
        return result.IsValid;
    }

    /// <summary>
    /// 简单校验Token有效性（只验证签名和过期时间）- 使用注入的配置
    /// </summary>
    /// <param name="encodeJwt">加密后的Jwt令牌</param>
    /// <returns>Token是否有效</returns>
    public Boolean IsValidToken(String encodeJwt) => IsValidToken(encodeJwt, _jwtOptions.Value);

    /// <summary>
    /// 简单校验Token有效性并返回详细结果
    /// </summary>
    /// <param name="encodeJwt">加密后的Jwt令牌</param>
    /// <param name="options">Jwt选项配置</param>
    /// <returns>包含验证结果和解析数据的对象</returns>
    public TokenValidationResult IsValidTokenWithResult(String encodeJwt, JwtOptions options)
    {
        try
        {
            if (encodeJwt.IsNullOrWhiteSpace() || options?.Secret.IsNullOrWhiteSpace() == true)
                return TokenValidationResult.Failure(encodeJwt, "Token或配置为空");

            var jwtArray = encodeJwt.Split('.');
            if (jwtArray.Length < 3)
                return TokenValidationResult.Failure(encodeJwt, "Token格式无效");

            // 解析header和payload
            var header = JsonHelper.ToJsonEntity<Dictionary<String, String>>(Base64UrlEncoder.Decode(jwtArray[0]));
            var payload = JsonHelper.ToJsonEntity<Dictionary<String, String>>(Base64UrlEncoder.Decode(jwtArray[1]));

            // 验证签名
            var hs256 = new HMACSHA256(Encoding.UTF8.GetBytes(options.Secret));
            var computedSign = Base64UrlEncoder.Encode(
                hs256.ComputeHash(Encoding.UTF8.GetBytes(String.Concat(jwtArray[0], ".", jwtArray[1]))));

            if (!String.Equals(jwtArray[2], computedSign))
                return TokenValidationResult.Failure(encodeJwt, "Token签名验证失败");

            // 验证过期时间
            if (payload?.ContainsKey("exp") == true)
            {
                if (Int64.TryParse(payload["exp"], out var expTimeStamp))
                {
                    var expTime = DateTimeOffset.FromUnixTimeSeconds(expTimeStamp);
                    if (expTime <= DateTimeOffset.UtcNow)
                        return TokenValidationResult.Failure(encodeJwt, "Token已过期");
                }
            }

            // 验证生效时间
            if (payload?.ContainsKey("nbf") == true)
            {
                if (Int64.TryParse(payload["nbf"], out var nbfTimeStamp))
                {
                    var nbfTime = DateTimeOffset.FromUnixTimeSeconds(nbfTimeStamp);
                    if (nbfTime > DateTimeOffset.UtcNow)
                        return TokenValidationResult.Failure(encodeJwt, "Token尚未生效");
                }
            }

            return TokenValidationResult.Success(encodeJwt, payload, header);
        }
        catch (Exception ex)
        {
            return TokenValidationResult.Failure(encodeJwt, $"Token验证异常: {ex.Message}");
        }
    }

    /// <summary>
    /// 简单校验Token有效性并返回详细结果 - 使用注入的配置
    /// </summary>
    /// <param name="encodeJwt">加密后的Jwt令牌</param>
    /// <returns>包含验证结果和解析数据的对象</returns>
    public TokenValidationResult IsValidTokenWithResult(String encodeJwt) => IsValidTokenWithResult(encodeJwt, _jwtOptions.Value);
}
