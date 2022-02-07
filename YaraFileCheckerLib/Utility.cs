using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using SevenZip;
using Vostok.Logging.Abstractions;

namespace YaraFileCheckerLib;

public partial class FileChecker
{
    public static string WildcardToRegex(string wildcardString)
        => "^" + Regex.Escape(wildcardString).Replace("\\*", ".*").Replace("\\?", ".") + "$";

    public static string GetSizeInMemory(long bytesize)
    {
        string[] sizes = { "B", "KB", "MB", "GB", "TB" };
        var len = Convert.ToDouble(bytesize);
        var order = 0;
        while (len >= 1024D && order < sizes.Length - 1)
        {
            order++;
            len /= 1024;
        }

        return string.Format(CultureInfo.CurrentCulture, "{0:0.##} {1}", len, sizes[order]);
    }

    public bool IsArchive(FileObject fileObject, ScanConfig scanConfig)
    {
        if (fileObject.Name != null && NameCheckByWildcardList(fileObject.Name, scanConfig.ArchiveFileTypes))
        {
            return true;
        }

        try
        {
            using var memoryStream = new MemoryStream(fileObject.Bytes);
            using var sevenZipExtractor = new SevenZipExtractor(memoryStream);
            return ExtractorCheck(sevenZipExtractor, scanConfig);
        }
        catch
        {
            return false;
        }
    }

    private static byte[] StreamToByteArray(Stream stream)
        => stream is MemoryStream memoryStream ? memoryStream.ToArray() : ReadFully(stream);

    private static byte[] ReadFully(Stream input)
    {
        using var ms = new MemoryStream();
        input.CopyTo(ms);
        return ms.ToArray();
    }

    private static bool NameCheckByWildcardList(string name, IEnumerable<string> list)
        => list.Any(f => Regex.IsMatch(name, WildcardToRegex(f), RegexOptions.IgnoreCase));

    private bool ExtractorCheck(SevenZipExtractor extractor, ScanConfig scanConfig)
    {
        var res = true;

        if ((extractor.UnpackedSize + scanConfig.ProcessingLimits.TotalBytes) / 1024 <= scanConfig.FileSizeLimitKb)
        {
            try
            {
                if (extractor.ArchiveFileData.FirstOrDefault(x => x.IsDirectory == false).FileName == null)
                {
                    return true;
                }

                using var stream = new MemoryStream();
                var fileIndex = extractor.ArchiveFileData.FirstOrDefault(x => x.IsDirectory == false).Index;
                extractor.ExtractFile(fileIndex, stream);
                if (stream.Length == 0)
                {
                    res = false;
                }
            }
            catch (Exception ex)
            {
                res = false;
            }
        }
        else
        {
            res = false;
        }

        return res;
    }
}