using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;

namespace WowRdpPatcher
{
    public class Program
    {
        private static readonly byte[] peHeader = Encoding.ASCII.GetBytes("PE\0\0");
        private static readonly byte[] rdataHeader = Encoding.ASCII.GetBytes(".rdata\0\0");
        private static readonly byte[] rdpStringBytes = Encoding.ASCII.GetBytes("Running World of Warcraft through a Remote Desktop");

        public static void Main(string[] args)
        {
            Console.Title = "Wow RDP Patcher";
            ColorPrint(@"  _      __             ___  ___  ___    ___       __      __          ", ConsoleColor.White);
            ColorPrint(@" | | /| / /__ _    __  / _ \/ _ \/ _ \  / _ \___ _/ /_____/ /  ___ ____", ConsoleColor.White);
            ColorPrint(@" | |/ |/ / _ \ |/|/ / / , _/ // / ___/ / ___/ _ `/ __/ __/ _ \/ -_) __/", ConsoleColor.White);
            ColorPrint(@" |__/|__/\___/__,__/ /_/|_/____/_/    /_/   \_,_/\__/\__/_//_/\__/_/   ", ConsoleColor.White);
            ColorPrint($"                                      Version: ", $"{Assembly.GetEntryAssembly().GetName().Version}\n", ConsoleColor.Yellow);

            if (args.Length < 1)
            {
                ColorPrint(">> Drop an *.exe on me...");
            }
            else
            {
                string file = args[0];

                if (string.IsNullOrEmpty(file))
                {
                    ColorPrint(">> Invalid filepath...");
                }
                else
                {
                    if (File.Exists(file))
                    {
                        byte[] exeBytes = File.ReadAllBytes(file);

                        if (exeBytes[0] != 'M' || exeBytes[1] != 'Z')
                        {
                            ColorPrint($">> {Path.GetFileName(file)} is not a valid PE file...", ConsoleColor.Red);
                        }
                        else
                        {
                            FileVersionInfo versionInfo = FileVersionInfo.GetVersionInfo(file);
                            ColorPrint($">> File version:\t\t", versionInfo.FileVersion, ConsoleColor.Yellow);

                            if (FindByteSequence(exeBytes, rdpStringBytes, out int stringOffset))
                            {
                                if (FindByteSequence(exeBytes, peHeader, out int peHeaderOffset))
                                {
                                    if (FindByteSequence(exeBytes, rdataHeader, out int rdataOffset))
                                    {
                                        // for wow this should be 0x400000
                                        int imageBase = BitConverter.ToInt32(exeBytes, peHeaderOffset + 0x34);
                                        ColorPrint($">> PE ImageBase:\t\t", $"0x{imageBase:X}", ConsoleColor.Cyan);

                                        rdataOffset += imageBase;
                                        ColorPrint($">> .rdata section at:\t\t", $"0x{rdataOffset:X}", ConsoleColor.Cyan);

                                        // the string is stored in the .rdata section
                                        int virtualAddress = BitConverter.ToInt32(exeBytes, rdataOffset - imageBase + 12);
                                        int pointerToRawData = BitConverter.ToInt32(exeBytes, rdataOffset - imageBase + 20);

                                        ColorPrint($">> VirtualAddress:\t\t", $"0x{virtualAddress:X}", ConsoleColor.Cyan);
                                        ColorPrint($">> PointerToRawData:\t\t", $"0x{pointerToRawData:X}", ConsoleColor.Cyan);

                                        // virtual memory offset to find the usage of our string
                                        int vaOffset = virtualAddress - pointerToRawData;
                                        ColorPrint($">> Virtual Address Offset:\t", $"0x{vaOffset:X}", ConsoleColor.Cyan);

                                        // add base offset
                                        stringOffset += imageBase + vaOffset;
                                        ColorPrint(">> Found RDP string at:\t\t", $"0x{stringOffset:X}", ConsoleColor.Cyan);

                                        // we will look for the place, where the string gets loaded
                                        // 0x68 = PUSH
                                        byte[] stringOffsetBytes = BitConverter.GetBytes(stringOffset);
                                        byte[] bytesRdpCheck = new byte[] { 0x68, 0x00, 0x00, 0x00, 0x00 };

                                        // copy the string offset behind the push instruction
                                        Array.Copy(stringOffsetBytes, 0, bytesRdpCheck, 1, 4);

                                        StringBuilder sbRdpCheck = new();

                                        for (int i = 0; i < 5; ++i)
                                        {
                                            sbRdpCheck.Append($"0x{bytesRdpCheck[i]:X} ");
                                        }

                                        ColorPrint($">> Searching RDP string PUSH:\t", sbRdpCheck.ToString(), ConsoleColor.Cyan);

                                        if (FindByteSequence(exeBytes, bytesRdpCheck, out int offset))
                                        {
                                            ColorPrint(">> Found RDP check function at: ", $"0x{offset:X}", ConsoleColor.Cyan);

                                            if (exeBytes[offset] == 0x90)
                                            {
                                                ColorPrint($">> Wow is already patched");
                                            }
                                            else
                                            {
                                                string backupFilename = $"{file}.backup";

                                                File.WriteAllBytes(backupFilename, exeBytes);
                                                ColorPrint($">> Backup exe:\t\t\t", Path.GetFileName(backupFilename), ConsoleColor.Green);

                                                StringBuilder sbRdpFunc = new();

                                                // fill the next 15 bytes with NOP's to prevent wow
                                                // from exiting
                                                for (int i = 0; i < 15; ++i)
                                                {
                                                    sbRdpFunc.Append($"0x{exeBytes[offset + i]:X} ");
                                                    exeBytes[offset + i] = 0x90; // NOP
                                                }

                                                ColorPrint($">> Replaced bytes with NOP:\t", sbRdpFunc.ToString(), ConsoleColor.Cyan);
                                                File.WriteAllBytes(file, exeBytes);

                                                ColorPrint(">> Patching: ", "successful", ConsoleColor.Green);
                                            }
                                        }
                                        else
                                        {
                                            ColorPrint(">> Unable to locate rdp check function...", ConsoleColor.Red);
                                            ColorPrint(">> Executeable is already patched or incompatible...");
                                        }
                                    }
                                    else
                                    {
                                        ColorPrint(">> Unable to locate .rdata section header...", ConsoleColor.Red);
                                    }
                                }
                                else
                                {
                                    ColorPrint(">> Unable to locate PE header...", ConsoleColor.Red);
                                }
                            }
                            else
                            {
                                ColorPrint(">> Unable to locate RDP string", ConsoleColor.Red);
                            }
                        }
                    }
                    else
                    {
                        ColorPrint(">> File not found...", ConsoleColor.Red);
                    }
                }
            }

            ColorPrint(">> Press a key to exit...");
            Console.ReadKey();
        }

        public static bool MatchSequence(byte[] bytes, int position, byte[] sequence)
        {
            if (sequence.Length > (bytes.Length - position))
            {
                return false;
            }

            for (int i = 0; i < sequence.Length; ++i)
            {
                if (bytes[position + i] != sequence[i])
                {
                    return false;
                }
            }

            return true;
        }

        private static void ColorPrint(string text, string coloredText, ConsoleColor color = ConsoleColor.White)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write(text);
            ColorPrint(coloredText, color);
        }

        private static void ColorPrint(string text, ConsoleColor color = ConsoleColor.White)
        {
            Console.ForegroundColor = color;
            Console.WriteLine(text);
            Console.ForegroundColor = ConsoleColor.White;
        }

        private static bool FindByteSequence(byte[] bytes, byte[] sequence, out int offset)
        {
            for (int i = 0; i < bytes.Length; ++i)
            {
                if (MatchSequence(bytes, i, sequence))
                {
                    offset = i;
                    return true;
                }
            }

            offset = 0;
            return false;
        }
    }
}