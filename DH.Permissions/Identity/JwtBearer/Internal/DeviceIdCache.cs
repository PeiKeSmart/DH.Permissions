using Pek.Webs;

namespace DH.Permissions.Identity.JwtBearer.Internal;

/// <summary>
/// 设备ID缓存辅助类
/// 用于在单次请求中缓存设备ID，避免重复计算
/// </summary>
internal static class DeviceIdCache
{
    /// <summary>
    /// 设备ID缓存键
    /// </summary>
    private const String DeviceIdCacheKey = "JWT_DEVICE_ID_CACHE";
    
    /// <summary>
    /// 获取设备ID（带缓存）
    /// </summary>
    /// <param name="httpContext">HTTP上下文</param>
    /// <returns>设备ID</returns>
    public static String GetDeviceId(Microsoft.AspNetCore.Http.HttpContext httpContext)
    {
        if (httpContext?.Items == null)
            return DHWebHelper.FillDeviceId(httpContext);
            
        // 尝试从缓存获取
        if (httpContext.Items.TryGetValue(DeviceIdCacheKey, out var cachedDeviceId))
        {
            return cachedDeviceId as String;
        }
        
        // 缓存中没有，计算并缓存
        var deviceId = DHWebHelper.FillDeviceId(httpContext);
        httpContext.Items[DeviceIdCacheKey] = deviceId;
        
        return deviceId;
    }
    
    /// <summary>
    /// 设置设备ID缓存
    /// </summary>
    /// <param name="httpContext">HTTP上下文</param>
    /// <param name="deviceId">设备ID</param>
    public static void SetDeviceId(Microsoft.AspNetCore.Http.HttpContext httpContext, String deviceId)
    {
        if (httpContext?.Items == null)
            return;
            
        httpContext.Items[DeviceIdCacheKey] = deviceId;
    }
    
    /// <summary>
    /// 清除设备ID缓存
    /// </summary>
    /// <param name="httpContext">HTTP上下文</param>
    public static void ClearDeviceId(Microsoft.AspNetCore.Http.HttpContext httpContext)
    {
        if (httpContext?.Items == null)
            return;
            
        httpContext.Items.Remove(DeviceIdCacheKey);
    }
    
    /// <summary>
    /// 检查是否已缓存设备ID
    /// </summary>
    /// <param name="httpContext">HTTP上下文</param>
    /// <returns>是否已缓存</returns>
    public static Boolean HasCachedDeviceId(Microsoft.AspNetCore.Http.HttpContext httpContext)
    {
        return httpContext?.Items?.ContainsKey(DeviceIdCacheKey) == true;
    }
}
