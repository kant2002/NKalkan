using System;
using System.Runtime.InteropServices;
using System.Text;

namespace NKalkan;

internal static class KalkanUtils
{
    public static string ReadUtf8(IntPtr ptr, int len)
    {
        if (ptr == IntPtr.Zero || len <= 0) return string.Empty;

        // защита от совсем странных значений
        if (len > 1024 * 1024) return $"[outInfo too large: {len}]";

        var bytes = new byte[len];
        Marshal.Copy(ptr, bytes, 0, len);
        return Encoding.UTF8.GetString(bytes).TrimEnd('\0');
    }

    public static byte[] ReadBytes(IntPtr ptr, int len)
    {
        if (ptr == IntPtr.Zero || len <= 0) return Array.Empty<byte>();
        if (len > 10 * 1024 * 1024) return Array.Empty<byte>();

        var bytes = new byte[len];
        Marshal.Copy(ptr, bytes, 0, len);
        return bytes;
    }
}
