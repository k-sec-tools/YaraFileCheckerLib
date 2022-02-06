using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace YaraFileCheckerLib
{
    public interface IFileScanResult
    {
        public bool ScanSuccessful { get; set; }
        public string FileName { get; set; }
        public List<string> MatchedRules { get; set; }
        public bool Executable { get; set; }
        public bool Dangerous { get; set; }
    }
}
