// The build-time self-test of ctf-runtime-dotnet (B-242): our own assembly, never a delivered one.
// The token is built in the static constructor, so finding it in the trace proves the runner ran it.
using System.Text;

public static class Selftest
{
    static readonly string Token;

    static Selftest()
    {
        var b = new StringBuilder();
        foreach (char c in "dug.tfmguftu.pl") b.Append((char)(c - 1));
        Token = b.ToString();
    }

    public static bool Check(string s) { return Token == s; }
}
