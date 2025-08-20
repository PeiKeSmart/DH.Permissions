using Microsoft.AspNetCore.Http;

namespace DH.Permissions.Identity.JwtBearer.Internal;

/// <summary>
/// Token验证缓存辅助类
/// 用于在单次请求中缓存Token解析结果，避免重复解析
/// </summary>
internal static class TokenValidationCache
{
    /// <summary>
    /// 缓存键前缀
    /// </summary>
    private const String CacheKeyPrefix = "JWT_VALIDATION_CACHE_";
    
    /// <summary>
    /// 从HttpContext中获取缓存的Token验证结果
    /// </summary>
    /// <param name="httpContext">HTTP上下文</param>
    /// <param name="token">Token字符串</param>
    /// <returns>缓存的验证结果，如果不存在则返回null</returns>
    public static TokenValidationResult GetCachedResult(HttpContext httpContext, String token)
    {
        if (httpContext?.Items == null || String.IsNullOrWhiteSpace(token))
            return null;
            
        var cacheKey = GetCacheKey(token);
        return httpContext.Items.TryGetValue(cacheKey, out var cachedResult) 
            ? cachedResult as TokenValidationResult 
            : null;
    }
    
    /// <summary>
    /// 将Token验证结果缓存到HttpContext中
    /// </summary>
    /// <param name="httpContext">HTTP上下文</param>
    /// <param name="token">Token字符串</param>
    /// <param name="result">验证结果</param>
    public static void SetCachedResult(HttpContext httpContext, String token, TokenValidationResult result)
    {
        if (httpContext?.Items == null || String.IsNullOrWhiteSpace(token) || result == null)
            return;
            
        var cacheKey = GetCacheKey(token);
        httpContext.Items[cacheKey] = result;
    }
    
    /// <summary>
    /// 从HttpContext中移除缓存的Token验证结果
    /// </summary>
    /// <param name="httpContext">HTTP上下文</param>
    /// <param name="token">Token字符串</param>
    public static void RemoveCachedResult(HttpContext httpContext, String token)
    {
        if (httpContext?.Items == null || String.IsNullOrWhiteSpace(token))
            return;
            
        var cacheKey = GetCacheKey(token);
        httpContext.Items.Remove(cacheKey);
    }
    
    /// <summary>
    /// 清除HttpContext中所有的Token验证缓存
    /// </summary>
    /// <param name="httpContext">HTTP上下文</param>
    public static void ClearAllCachedResults(HttpContext httpContext)
    {
        if (httpContext?.Items == null)
            return;
            
        var keysToRemove = httpContext.Items.Keys
            .Where(key => key is String keyStr && keyStr.StartsWith(CacheKeyPrefix))
            .ToList();
            
        foreach (var key in keysToRemove)
        {
            httpContext.Items.Remove(key);
        }
    }
    
    /// <summary>
    /// 生成缓存键
    /// </summary>
    /// <param name="token">Token字符串</param>
    /// <returns>缓存键</returns>
    private static String GetCacheKey(String token)
    {
        // 使用Token的哈希值作为缓存键，避免在HttpContext.Items中存储完整的Token
        var tokenHash = token.GetHashCode().ToString();
        return $"{CacheKeyPrefix}{tokenHash}";
    }
}
