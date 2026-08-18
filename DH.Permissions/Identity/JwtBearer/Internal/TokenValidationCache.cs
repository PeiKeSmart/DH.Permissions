using Microsoft.AspNetCore.Http;

namespace DH.Permissions.Identity.JwtBearer.Internal;

/// <summary>
/// Token验证缓存辅助类
/// 用于在单次请求中缓存Token解析结果，避免重复解析
/// </summary>
internal static class TokenValidationCache
{
    /// <summary>
    /// HttpContext.Items中的缓存容器键
    /// </summary>
    private static readonly Object CacheKey = new();
    
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

        return TryGetCache(httpContext, out var cache) && cache.TryGetValue(token, out var cachedResult)
            ? cachedResult
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

        var cache = GetOrCreateCache(httpContext);
        cache[token] = result;
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

        if (!TryGetCache(httpContext, out var cache))
            return;

        cache.Remove(token);
        if (cache.Count == 0)
            httpContext.Items.Remove(CacheKey);
    }
    
    /// <summary>
    /// 清除HttpContext中所有的Token验证缓存
    /// </summary>
    /// <param name="httpContext">HTTP上下文</param>
    public static void ClearAllCachedResults(HttpContext httpContext)
    {
        if (httpContext?.Items == null)
            return;

        httpContext.Items.Remove(CacheKey);
    }
    
    /// <summary>
    /// 尝试获取缓存容器
    /// </summary>
    /// <param name="httpContext">HTTP上下文</param>
    /// <param name="cache">缓存容器</param>
    /// <returns>是否获取成功</returns>
    private static Boolean TryGetCache(HttpContext httpContext, out Dictionary<String, TokenValidationResult> cache)
    {
        if (httpContext.Items.TryGetValue(CacheKey, out var cacheObject) && cacheObject is Dictionary<String, TokenValidationResult> tokenCache)
        {
            cache = tokenCache;
            return true;
        }

        cache = null;
        return false;
    }

    /// <summary>
    /// 获取或创建缓存容器
    /// </summary>
    /// <param name="httpContext">HTTP上下文</param>
    /// <returns>缓存容器</returns>
    private static Dictionary<String, TokenValidationResult> GetOrCreateCache(HttpContext httpContext)
    {
        if (TryGetCache(httpContext, out var cache))
            return cache;

        cache = new Dictionary<String, TokenValidationResult>(StringComparer.Ordinal);
        httpContext.Items[CacheKey] = cache;
        return cache;
    }
}
