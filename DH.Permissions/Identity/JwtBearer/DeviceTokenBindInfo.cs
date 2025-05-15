using Pek.Security;

namespace DH.Permissions.Identity.JwtBearer;

/// <summary>
/// 设备令牌绑定信息
/// </summary>
[Serializable]
public class DeviceTokenBindInfo
{
    /// <summary>
    /// 用户标识
    /// </summary>
    public String UserId { get; set; }

    /// <summary>
    /// 设备标识
    /// </summary>
    public String DeviceId { get; set; }

    /// <summary>
    /// 设备类型
    /// </summary>
    public String DeviceType { get; set; }

    /// <summary>
    /// 令牌
    /// </summary>
    public JsonWebToken Token { get; set; }
}
