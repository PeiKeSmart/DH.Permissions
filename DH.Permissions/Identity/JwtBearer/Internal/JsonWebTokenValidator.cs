using System.Security.Cryptography;
using System.Text;

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

using NewLife;
using NewLife.Log;
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
        XTrace.WriteLineSafe($"JWT验证器开始验证Token：{encodeJwt?.Substring(0, Math.Min(20, encodeJwt?.Length ?? 0))}...");
        
        if (options.Secret.IsNullOrWhiteSpace())
        {
            XTrace.WriteLineSafe("JWT验证器失败：Secret配置为空");
            throw new ArgumentNullException(nameof(options.Secret),
                $@"{nameof(options.Secret)}为Null或空字符串。请在""appsettings.json""配置""{nameof(JwtOptions)}""节点及其子节点""{nameof(JwtOptions.Secret)}""");
        }
        
        var jwtArray = encodeJwt.Split('.');
        if (jwtArray.Length < 3)
        {
            XTrace.WriteLineSafe($"JWT验证器失败：Token格式错误，分段数量={jwtArray.Length}");
            return false;
        }
        
        var header = JsonHelper.ToJsonEntity<Dictionary<String, String>>(Base64UrlEncoder.Decode(jwtArray[0]));
        var payload = JsonHelper.ToJsonEntity<Dictionary<String, String>>(Base64UrlEncoder.Decode(jwtArray[1]));
        XTrace.WriteLineSafe($"JWT验证器解析Header成功：{header?.ToJson()}");
        XTrace.WriteLineSafe($"JWT验证器解析Payload成功，用户={payload?.GetOrDefault("sub")}, From={payload?.GetOrDefault("From")}");

        // 首先验证签名是否正确
        var hs256 = new HMACSHA256(Encoding.UTF8.GetBytes(options.Secret));
        var sign = Base64UrlEncoder.Encode(
            hs256.ComputeHash(Encoding.UTF8.GetBytes(String.Concat(jwtArray[0], ".", jwtArray[1]))));
        // 签名不正确直接返回
        if (!String.Equals(jwtArray[2], sign))
        {
            XTrace.WriteLineSafe("JWT验证器失败：签名验证失败");
            return false;
        }
        
        XTrace.WriteLineSafe("JWT验证器签名验证成功");
        
        // 其次验证是否在有效期内
        //var now = ToUnixEpochDate(DateTime.UtcNow);
        //if (!(now >= long.Parse(payload["nbf"].ToString()) && now < long.Parse(payload["exp"].ToString())))
        //    return false;
        // 进行自定义验证
        var customValidateResult = validatePayload(payload, options);
        XTrace.WriteLineSafe($"JWT验证器自定义验证结果：{customValidateResult}");
        
        return customValidateResult;
    }    
    
    /// <summary>
    /// 简单校验Token有效性（只验证签名和过期时间）
    /// </summary>
    /// <param name="encodeJwt">加密后的Jwt令牌</param>
    /// <param name="options">Jwt选项配置</param>
    /// <returns>Token是否有效</returns>
    public Boolean IsValidToken(String encodeJwt, JwtOptions options)
    {
        try
        {
            XTrace.WriteLineSafe($"JWT验证器简单验证Token：{encodeJwt?.Substring(0, Math.Min(20, encodeJwt?.Length ?? 0))}...");
            
            if (encodeJwt.IsNullOrWhiteSpace() || options?.Secret.IsNullOrWhiteSpace() == true)
            {
                XTrace.WriteLineSafe("JWT验证器简单验证失败：Token或Secret为空");
                return false;
            }

            var jwtArray = encodeJwt.Split('.');
            if (jwtArray.Length < 3)
            {
                XTrace.WriteLineSafe($"JWT验证器简单验证失败：Token格式错误，分段数量={jwtArray.Length}");
                return false;
            }

            // 验证签名
            var hs256 = new HMACSHA256(Encoding.UTF8.GetBytes(options.Secret));
            var computedSign = Base64UrlEncoder.Encode(
                hs256.ComputeHash(Encoding.UTF8.GetBytes(String.Concat(jwtArray[0], ".", jwtArray[1]))));
            
            if (!String.Equals(jwtArray[2], computedSign))
            {
                XTrace.WriteLineSafe("JWT验证器简单验证失败：签名验证失败");
                return false;
            }

            // 验证过期时间
            var payload = JsonHelper.ToJsonEntity<Dictionary<String, String>>(Base64UrlEncoder.Decode(jwtArray[1]));
            if (payload?.ContainsKey("exp") == true)
            {
                if (Int64.TryParse(payload["exp"], out var expTimeStamp))
                {
                    var expTime = DateTimeOffset.FromUnixTimeSeconds(expTimeStamp);
                    if (expTime <= DateTimeOffset.UtcNow)
                    {
                        XTrace.WriteLineSafe($"JWT验证器简单验证失败：Token已过期，过期时间={expTime}, 当前时间={DateTimeOffset.UtcNow}");
                        return false;
                    }
                }
            }

            // 验证生效时间
            if (payload?.ContainsKey("nbf") == true)
            {
                if (Int64.TryParse(payload["nbf"], out var nbfTimeStamp))
                {
                    var nbfTime = DateTimeOffset.FromUnixTimeSeconds(nbfTimeStamp);
                    if (nbfTime > DateTimeOffset.UtcNow)
                    {
                        XTrace.WriteLineSafe($"JWT验证器简单验证失败：Token未生效，生效时间={nbfTime}, 当前时间={DateTimeOffset.UtcNow}");
                        return false;
                    }
                }
            }

            XTrace.WriteLineSafe("JWT验证器简单验证成功");
            return true;
        }
        catch (Exception ex)
        {
            XTrace.WriteLineSafe($"JWT验证器简单验证异常：{ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// 简单校验Token有效性（只验证签名和过期时间）- 使用注入的配置
    /// </summary>
    /// <param name="encodeJwt">加密后的Jwt令牌</param>
    /// <returns>Token是否有效</returns>
    public Boolean IsValidToken(String encodeJwt) => IsValidToken(encodeJwt, _jwtOptions.Value);
}
