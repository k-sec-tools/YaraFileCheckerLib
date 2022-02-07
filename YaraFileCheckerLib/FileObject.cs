using System;

namespace YaraFileCheckerLib;

public class FileObject
{
    public FileObject(byte[] bytes, string name = null)
    {
        Bytes = bytes;
        Name = name;
    }

    public byte[] Bytes { get; set; }
    public string Name { get; set; }
}