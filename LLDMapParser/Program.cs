using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace LLDMapParser
{
  class Program
  {
    /// <summary>
    /// Parses pre-march-2017 LLD .map files into .idc scripts
    /// </summary>
    /// <param name="args">arg[0] should be the input filename</param>
    static void Main(string[] args)
    {
      // First argument is the input and output filename. ".idc" is appended to the out filename
      var filename = args[0];
      var outputFilename = filename + ".idc";
      var symbols = new List<(string symbol, int address)>();
      using (var sr = new StreamReader(filename))
      {
        // Get the column indices
        // Address  Size     Align Out     In      File    Symbol
        var header = sr.ReadLine();
        var addressCol = header.IndexOf("Address");
        var sizeCol = header.IndexOf("Size");
        var alignCol = header.IndexOf("Align"); // note: this is right-aligned
        var outCol = header.IndexOf("Out");
        var inCol = header.IndexOf("In");
        var fileCol = header.IndexOf("File");
        var symbolCol = header.IndexOf("Symbol");
        sr.ReadLine(); //ignore
        //=================================================================
        // Read the symbols
        while (!sr.EndOfStream)
        {
          var line = sr.ReadLine();
          var addressStr = line.Substring(addressCol, sizeCol - addressCol).Trim();
          if (addressStr == "UNDEFINED" || addressStr == "")
          {
            // TODO: handle 'undefined' symbols
            continue;
          }
          // Address, size, and align are hex numbers
          var address = int.Parse(addressStr, NumberStyles.AllowHexSpecifier);
          var size = int.Parse(line.Substring(sizeCol, alignCol - sizeCol).Trim(), NumberStyles.AllowHexSpecifier);
          var align = int.Parse(line.Substring(alignCol, 5).Trim(), NumberStyles.AllowHexSpecifier);

          // Skip Out for now
          if (line[outCol] != ' ')
            continue;
          // Skip In for now
          if (line[inCol] != ' ')
            continue;
          // Skip File for now
          if (line[fileCol] != ' ')
            continue;
          // Collect all symbols in a list of (symbol, address) pairs
          if (line[symbolCol] != ' ')
          {
            if (address != 0) // HACK: I guess a lot of symbols have a zero address, let's ignore them
              symbols.Add((line.Substring(symbolCol).Trim(), address));
          }
        }
      }
      // Make the symbols in ascending address order
      symbols.Sort((x, y) => x.address.CompareTo(y.address));
      var clean_symbols = new Dictionary<string, int>();
      using (var writer = new StreamWriter(outputFilename))
      {
        writer.WriteLine("static main() {");
        foreach (var (name, address) in symbols.Distinct())
        {
          // IDA doesn't really like non-alphanumeric/underscore characters
          // TODO: Can we re-mangle the names to get a nice signature in the IDA function view?
          var cleanName = Regex.Replace(name, "[^a-zA-Z0-9_]", y => "_");
          int suffix = 1;
          // Name collisions abound because LLD doesn't differentiate some destructors by name
          if(clean_symbols.ContainsKey(cleanName))
          {
            suffix = clean_symbols[cleanName] + 1;
          }
          // Set the name of the address to the cleaned name
          writer.WriteLine($"set_name(0x{address:X2}, \"{cleanName + (suffix > 1 ? suffix.ToString() : "")}\", 0);");
          // Set the repeatable comment at that address to the full name
          writer.WriteLine($"set_cmt(0x{address:X2}, \"{name}\", 1);");
          // Remember the clean name so we can un-collide it later
          clean_symbols[cleanName] = suffix;
        }
        writer.WriteLine("}");
      }
    }
  }
}
