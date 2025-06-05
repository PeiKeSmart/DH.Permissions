namespace DH.Permissions.Identity.JwtBearer;

/// <summary>
/// 令牌Payload存储器
/// </summary>
public interface ITokenPayloadStore
{
    /// <summary>
    /// 保存
    /// </summary>
    /// <param name="token">令牌</param>
    /// <param name="payload">负载字典</param>
    /// <param name="expires">过期时间</param>
    void Save(String token, IDictionary<String, String> payload, DateTime expires);

    /// <summary>
    /// 移除
    /// </summary>
    /// <param name="token">令牌</param>
    void Remove(String token);

    /// <summary>
    /// 延时移除
    /// </summary>
    /// <param name="token">令牌</param>
    /// <param name="expire">过期时间</param>
    void Remove(String token, Int32 expire);

    /// <summary>
    /// 获取Payload
    /// </summary>
    /// <param name="token">令牌</param>
    IDictionary<String, String> Get(String token);
}
