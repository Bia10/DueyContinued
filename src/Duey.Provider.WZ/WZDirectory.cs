using System.IO.MemoryMappedFiles;
using Duey.Abstractions;
using Duey.Provider.WZ.Codecs;
using Duey.Provider.WZ.Exceptions;
using Duey.Provider.WZ.Files;

namespace Duey.Provider.WZ;

public class WZDirectory : AbstractWZNode, IDataDirectory
{
    private readonly WZPackage _package;
    private readonly int _start;
    
    public WZDirectory(WZPackage package, int start, string name, IDataNode parent)
    {
        _package = package;
        _start = start;
        Name = name;
        Parent = parent;
    }
    
    public override string Name { get; }
    public override IDataNode Parent { get; }

    public override IEnumerable<IDataNode> Children
    {
        get
        {
            using var stream = _package.View.CreateViewStream(0, 0, MemoryMappedFileAccess.Read);
            using var reader = new WZReader(stream, _package.Cipher, _start, _package.Start);
            
            var count = reader.ReadCompressedInt();

            for (var i = 0; i < count; i++)
            {
                var type = reader.ReadByte();
                if (type > 4) throw new WZPackageException("Invalid type while parsing directory");

                string name;
                if (type <= 2)
                {
                    // Back-reference: offset points to the type byte of the original entry,
                    // followed by the inline name string. Skip the type byte before reading.
                    var nameOffset = reader.ReadInt32();
                    var resumePos = reader.BaseStream.Position;
                    reader.BaseStream.Position = _package.Start + nameOffset;
                    reader.ReadByte();
                    name = reader.ReadString();
                    reader.BaseStream.Position = resumePos;
                }
                else
                {
                    name = reader.ReadString();
                }

                reader.ReadCompressedInt();
                reader.ReadCompressedInt();

                var offset = reader.ReadOffset(_package.Start, _package.InternalKey);

                switch (type)
                {
                    case 1:
                    case 3:
                        yield return new WZDirectory(_package, offset, name, this);
                        break;
                    case 2:
                    case 4:
                        yield return new WZImage(_package.View, _package.Cipher, 0, offset, name, this);
                        break;
                }
            }
        }
    }
}
