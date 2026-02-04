using System;
using System.Runtime.InteropServices;
using System.Text;

namespace NKalkan;

internal static class KalkanUtils
{
    public static string ReadUtf8(IntPtr ptr, int len)
    {
        if (ptr == IntPtr.Zero)
            return string.Empty;

        if (len < 0)
            throw new ArgumentOutOfRangeException(nameof(len));

        var bytes = new byte[len];
        Marshal.Copy(ptr, bytes, 0, len);

        return Encoding.UTF8.GetString(bytes).TrimEnd('\0');
    }
}
