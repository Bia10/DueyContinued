using System.Text;
using Duey.Provider.WZ.Crypto;
using Duey.Provider.WZ.Files;
using Xunit;
using static Duey.Provider.WZ.Tests.WZTestHelpers;

namespace Duey.Provider.WZ.Tests;

/// <summary>
/// Tests that verify WZDirectory correctly yields children with back-reference names
/// (directory entry types 1 and 2).
///
/// Back-reference entries store a 4-byte offset that points to the type byte of the
/// original entry elsewhere in the WZ file, followed by the inline name string.
/// The type byte must be skipped before reading the name. Without the skip,
/// ReadString() interprets the type byte (0x03 or 0x04) as a positive string length
/// and reads garbled Unicode.
///
/// These tests use only directory entries (types 1 and 3) because WZDirectory
/// construction is lazy — no data is read at the target offset. Types 1 and 2 share
/// the same name resolution code path, so proving type 1 works also proves type 2.
/// </summary>
public class DirectoryBackRefTests
{
    private static readonly XORCipher Cipher = new(WZImageIV.GMS);

    // WZ header constants matching key "95"
    private const string WZKey = "95";
    private const int WZStart = 0x10;
    private const uint WZKeyUint = 1910u;
    private const byte WZHash = 0x8E;

    // Fixed positions in synthetic binary
    private const int BackRefTarget1 = 0x80;
    private const int BackRefTarget2 = 0xA0;

    [Fact]
    public void Type1BackRef_YieldsDirectoryWithCorrectName()
    {
        var data = BuildDirectoryData(
            backRefName: "logindir",
            inlineName: "otherdir"
        );

        using var mmf = CreateMemoryMappedFile(data);
        var package = new WZPackage(mmf, "test", WZKey, Cipher);

        var children = package.Children.ToList();

        Assert.Equal(2, children.Count);
        Assert.Equal("logindir", children[0].Name);
        Assert.IsType<WZDirectory>(children[0]);
    }

    [Fact]
    public void Type3Inline_StillWorksAlongsideBackRef()
    {
        var data = BuildDirectoryData(
            backRefName: "logindir",
            inlineName: "otherdir"
        );

        using var mmf = CreateMemoryMappedFile(data);
        var package = new WZPackage(mmf, "test", WZKey, Cipher);

        var children = package.Children.ToList();

        Assert.Equal(2, children.Count);
        Assert.Equal("otherdir", children[1].Name);
        Assert.IsType<WZDirectory>(children[1]);
    }

    [Fact]
    public void ChildCount_MatchesDeclaredCount()
    {
        var data = BuildDirectoryData(
            backRefName: "dir1",
            inlineName: "dir2"
        );

        using var mmf = CreateMemoryMappedFile(data);
        var package = new WZPackage(mmf, "test", WZKey, Cipher);

        Assert.Equal(2, package.Children.Count());
    }

    [Fact]
    public void BackRefAndInline_SameName_ProduceIdenticalResults()
    {
        const string sharedName = "testname";

        var data = BuildDirectoryData(
            backRefName: sharedName,
            inlineName: sharedName
        );

        using var mmf = CreateMemoryMappedFile(data);
        var package = new WZPackage(mmf, "test", WZKey, Cipher);

        var children = package.Children.ToList();

        Assert.Equal(children[0].Name, children[1].Name);
    }

    [Fact]
    public void MultipleBackRefs_AllResolvedCorrectly()
    {
        var data = BuildThreeEntryDirectoryData("backref1", "backref2", "inline1");

        using var mmf = CreateMemoryMappedFile(data);
        var package = new WZPackage(mmf, "test", WZKey, Cipher);

        var children = package.Children.ToList();

        Assert.Equal(3, children.Count);
        Assert.Equal("backref1", children[0].Name);
        Assert.Equal("backref2", children[1].Name);
        Assert.Equal("inline1", children[2].Name);
    }

    #region Binary builders

    /// <summary>
    /// Builds a synthetic WZ binary with a root directory containing 2 entries:
    ///   Entry 0: type 1 (directory, back-reference name)
    ///   Entry 1: type 3 (directory, inline name)
    /// </summary>
    private static byte[] BuildDirectoryData(string backRefName, string inlineName)
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms);

        WriteWZHeader(bw);

        // Directory data at WZStart + 2
        WriteCompressedInt(bw, 2); // count = 2

        // Entry 0: type 1 (directory, back-ref)
        bw.Write((byte)0x01);
        bw.Write(BackRefTarget1 - WZStart); // nameOffset (int32)
        WriteCompressedInt(bw, 0); // size
        WriteCompressedInt(bw, 0); // checksum
        long offsetPos0 = ms.Position;
        bw.Write(EncryptOffset(offsetPos0, WZStart, WZKeyUint, 0x200));

        // Entry 1: type 3 (directory, inline)
        bw.Write((byte)0x03);
        WriteWZString(bw, inlineName);
        WriteCompressedInt(bw, 0); // size
        WriteCompressedInt(bw, 0); // checksum
        long offsetPos1 = ms.Position;
        bw.Write(EncryptOffset(offsetPos1, WZStart, WZKeyUint, 0x200));

        // Back-reference target at BackRefTarget1: type byte + WZ string
        ms.Position = BackRefTarget1;
        bw.Write((byte)0x03); // referenced entry type byte (directory)
        WriteWZString(bw, backRefName);

        return PadToMinimumSize(ms.ToArray(), 4096);
    }

    /// <summary>
    /// Builds a synthetic WZ binary with 3 entries: two type-1 back-refs and one type-3 inline.
    /// </summary>
    private static byte[] BuildThreeEntryDirectoryData(string backRef1, string backRef2, string inline1)
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms);

        WriteWZHeader(bw);

        WriteCompressedInt(bw, 3); // count = 3

        // Entry 0: type 1, back-ref to BackRefTarget1
        bw.Write((byte)0x01);
        bw.Write(BackRefTarget1 - WZStart);
        WriteCompressedInt(bw, 0);
        WriteCompressedInt(bw, 0);
        long pos0 = ms.Position;
        bw.Write(EncryptOffset(pos0, WZStart, WZKeyUint, 0x200));

        // Entry 1: type 1, back-ref to BackRefTarget2
        bw.Write((byte)0x01);
        bw.Write(BackRefTarget2 - WZStart);
        WriteCompressedInt(bw, 0);
        WriteCompressedInt(bw, 0);
        long pos1 = ms.Position;
        bw.Write(EncryptOffset(pos1, WZStart, WZKeyUint, 0x200));

        // Entry 2: type 3, inline
        bw.Write((byte)0x03);
        WriteWZString(bw, inline1);
        WriteCompressedInt(bw, 0);
        WriteCompressedInt(bw, 0);
        long pos2 = ms.Position;
        bw.Write(EncryptOffset(pos2, WZStart, WZKeyUint, 0x200));

        // Back-reference targets
        ms.Position = BackRefTarget1;
        bw.Write((byte)0x03);
        WriteWZString(bw, backRef1);

        ms.Position = BackRefTarget2;
        bw.Write((byte)0x04); // type 4 at target — should be skipped, not affect name
        WriteWZString(bw, backRef2);

        return PadToMinimumSize(ms.ToArray(), 4096);
    }

    #endregion

    #region Helpers

    private static void WriteWZHeader(BinaryWriter bw)
    {
        bw.Write(0x31474B50);  // magic PKG1
        bw.Write(0);           // file size (ignored by parser)
        bw.Write(0);           // check (ignored by parser)
        bw.Write(WZStart);     // start offset
        // Stream is now at WZStart (0x10)
        bw.Write(WZHash);     // hash byte
        bw.Write((byte)0);    // skip byte
        // Stream is now at WZStart + 2 (0x12) — directory data follows
    }

    /// <summary>
    /// Writes a WZ string (for ReadString, not ReadStringBlock) with ASCII encoding.
    /// Same pipeline as WriteInlineStringBlock but without the string block type prefix.
    /// </summary>
    private static void WriteWZString(BinaryWriter bw, string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            bw.Write((sbyte)0);
            return;
        }

        var plaintext = Encoding.ASCII.GetBytes(value);
        bw.Write((sbyte)(-plaintext.Length));

        var encrypted = new byte[plaintext.Length];
        Buffer.BlockCopy(plaintext, 0, encrypted, 0, plaintext.Length);
        Cipher.Transform(encrypted);

        byte mask = 0xAA;
        for (var i = 0; i < encrypted.Length; i++)
        {
            encrypted[i] ^= mask;
            mask++;
        }

        bw.Write(encrypted);
    }

    /// <summary>
    /// Computes the encrypted uint32 value that ReadOffset will decode to targetOffset.
    /// This is the mathematical inverse of WZReader.ReadOffset.
    /// </summary>
    private static uint EncryptOffset(long streamPosition, int start, uint key, int targetOffset)
    {
        var offset = (uint)streamPosition;
        offset = (uint)(offset - start) ^ 0xFFFFFFFF;
        offset *= key;
        offset -= 0x581C3F6D;
        offset = ROL(offset, (byte)(offset & 0x1F));
        // ReadOffset: result = (offset ^ encrypted) + (uint)(start * 2)
        // So: encrypted = offset ^ (uint)(targetOffset - start * 2)
        return offset ^ (uint)((uint)targetOffset - (uint)(start * 2));
    }

    private static uint ROL(uint value, byte times) =>
        value << times | value >> (32 - times);

    #endregion
}
