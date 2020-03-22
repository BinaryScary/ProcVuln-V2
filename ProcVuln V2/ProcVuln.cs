using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

// TODO: context entry
// TODO: blacklist functionality
// TODO: error handling, file doesn't exists, ect

// Custom Entry Properties:
// "Privileged" : "True" # Process has integrity High or System
// "PathWritable" : "True" # Path is writable by current user
// "Context" : "" # used so entries can reference others, TBD how to implement
// "$Name" : {...} # Context entry, will not be shown in findings and can be used as Context property

namespace ProcVuln_V2
{
    class ProcVuln
    {
        string logPath;
        string indicatorPath;
        HashSet<string> privProcs; // best dataset for contains reference
        //Dictionary<string, Dictionary<string, string>> indicators; // holds entries from JSON file
        JObject indicators;
        List<Tuple<string, Dictionary<string, string>>> findings; // holds all possible findings with event

        ProcVuln(string lPath, string iPath)
        {
            logPath = lPath;
            indicatorPath = iPath;
            //indicators = new Dictionary<string, Dictionary<string, string>>();
            findings = new List<Tuple<string, Dictionary<string, string>>>();
        }

        //helper: ReadToFollowing, ReadElementContentAsString for subtree with checks
        string getSubPropString(XmlReader reader, string prop)
        {
            string value;
            reader.ReadToFollowing(prop);
            value = reader.ReadElementContentAsString();

            return value;
        }

        // add all High/System integrity processes to privProces, deserialization not needed due to simplicity/format
        void ParsePrivileged(XmlReader reader)
        {
            privProcs = new HashSet<string>();
            XmlReader node = reader.ReadSubtree(); // wrapper to delimit new xmlreader to only subtree, needs a read() to start
            XmlReader child; // child to read childe content 
            string integ;
            string value;
            node.ReadToDescendant("process"); // read to first <process> child node
            do
            {
                child = node.ReadSubtree();
                integ = getSubPropString(child, "Integrity");
                if (integ == "High" || integ == "System")
                {
                    value = getSubPropString(child, "ProcessName");
                    privProcs.Add(value);
                }
                child.Close();
            } while (node.ReadToNextSibling("process"));
        }

        //reader.Read(); // next element in line
        //reader.ReadStartElement(); // reads to first start element (without '/')
        //reader.ReadToDescendant("process"); // read to next child node with name
        //reader.ReadToFollowing("process"); // read to next node with name
        //reader.ReadToNextSibling("process"); // read to next sibling node with name
        //reader.ReadElementContentAsString(); // reads content moves pass end tag & stops at next element
        //XmlReader test = reader.ReadSubtree(); // reads & copies child nodes to seperate reader
        //test.Close() // close reader
        // helper: deserializes child nodes properties into dictionary
        Dictionary<string,string> deserializeSubtreeEvent(XmlReader reader)
        {
            XmlReader sub = reader.ReadSubtree();
            Dictionary<string, string> dict = new Dictionary<string, string>();
            sub.ReadToFollowing("ProcessIndex");
            while (true)
            {
                if (sub.IsStartElement())
                {
                    //Console.WriteLine("{0} : {1}", sub.Name, sub.ReadElementContentAsString());
                    dict.Add(sub.Name, sub.ReadElementContentAsString());
                    //sub.ReadElementContentAsString();
                }
                else { sub.Read(); } // reads past last element or dead element (error in procmon)

                if (sub.EOF) { break; }
            }

            return dict;
        }

        // generate JObjects from JSON
        void genIndicators()
        {
            // parse JSON file to JObject
            string jsonString = File.ReadAllText(indicatorPath);
            indicators = JObject.Parse(jsonString); 
        }

        // [Depricated] possibly implement again to deal with context entries
        // generate nested dictionaries from JSON (faster then dealing with JObjects)
        //void genIndicatorDicts()
        //{
        //    // parse JSON file to JObject
        //    string jsonString = File.ReadAllText(indicatorPath);
        //    JObject jsonEntries = JObject.Parse(jsonString); 

        //    // init global indicator dict of dict
        //    Dictionary<string, string> entryRef;

        //    // iterate over JObject
        //    foreach(JProperty entry in (JToken)jsonEntries)
        //    {
        //        entryRef = new Dictionary<string, string>();
        //        foreach(JProperty prop in ((JObject)entry.Value).Properties())
        //        {
        //            entryRef.Add(prop.Name, prop.Value.ToString());
        //            //Console.WriteLine(entry.Name + " - " + prop.Name + " - " + prop.Value);
        //        }
        //        indicators.Add(entry.Name, entryRef);
        //    }

        //}

        // maybe just use the C function I wrote for this?
        // TODO: Writable dir / file
            // TODO: cache the writable dirs/files?
        Boolean checkWritable(string path)
        {
            // does not have path property
            if(path == "") {
                return false;
            }

            // TODO: check if file exists, if it doesn't check if diretory exists or is writable
            // directory writable check
            //try
            //{
            //    System.Security.AccessControl.DirectorySecurity ds = Directory.GetAccessControl(path);
            //    return true;
            //}
            //catch (UnauthorizedAccessException)
            //{
            //    return false;
            //}
            return true; // placeholder
        }

        Boolean checkContext(JObject props, Dictionary<string,string> eventDict)
        {
            // check if entry exists and if that entry has a property that is equal
            JToken equal = props["equal"];
            if (equal != null)
            {
                string equals = equal.ToString();
                if (!findings.Any(m => m.Item1 == props["entry"].ToString() && m.Item2[equals] == eventDict[equals]))
                {
                    return false;
                }
            }
            else
            {
                if (!findings.Any(m => m.Item1 == props["entry"].ToString()))
                {
                    return false;
                }
            }
            //foreach(JProperty prop in ((JObject)context.Value).Properties())
            //{
            //}
            return true;
        }

        void checkEvent(Dictionary<string,string> eventDict)
        {
            Boolean privileged = privProcs.Contains(eventDict["Process_Name"]);
            Boolean writablePath = checkWritable(eventDict["Path"]); // TODO: check if dir/path is writable

            Boolean addEntry;
            string buff;

            foreach(JProperty entry in (JToken)indicators)
            {
                // TODO: refactor second loop into seperate function
                addEntry = true;
                foreach(JProperty prop in ((JObject)entry.Value).Properties())
                {
                    // check for if event was under privileged process or not (High, System)
                    if (prop.Name == "Privileged") {
                        if(prop.Value.ToString() == privileged.ToString()) {
                            continue;
                        }
                        else {
                            addEntry = false;
                            break;
                        }
                    }

                    // check if path dir/file is writable
                    if (prop.Name == "PathWritable") {
                        if(prop.Value.ToString() == writablePath.ToString()) {
                            continue;
                        }
                        else {
                            addEntry = false;
                            break;
                        }
                    }

                    // TODO: add context entry with distinguishers i.e: entry2 + path is the same
                    if (prop.Name == "Context")
                    {
                        if (checkContext((JObject)prop.Value, eventDict))
                        {
                            continue;
                        }
                        else
                        {
                            addEntry = false;
                            break;
                        }
                    }

                    // more efficient than exception or containskey
                    if (eventDict.TryGetValue(prop.Name, out buff)) {
                        // entry key was in event dictionary
                        if(prop.Value.ToString() == buff) {
                            continue;
                        }
                        else {
                            addEntry = false;
                            break;
                        }
                    } 
                    else {
                        // entry key wasn't in event dictionary, check fails
                        addEntry = false;
                        break;
                    }
                }

                if(addEntry == true)
                {
                    //Console.WriteLine(entry.Key);
                    findings.Add(new Tuple<string, Dictionary<string, string>>(entry.Name,eventDict)); // TODO: Add function which checks for same enteries and ignores Time_of_Day?
                }

            }
        }

        void Parser()
        {
            //genIndicatorDicts();
            genIndicators();

            // create XmlReader, Ignore whitespace
            // XMLReader performance: https://web.archive.org/web/20130517114458/http://www.nearinfinity.com/blogs/joe_ferner/performance_linq_to_sql_vs.html
            // XMLReader can only read iteratively (all reads will change reader position!), no deep copies since it is a file handle
            XmlReaderSettings settings = new XmlReaderSettings();
            settings.IgnoreWhitespace = true;
            XmlReader reader = XmlReader.Create(logPath, settings);

            // read to processlist
            reader.ReadToFollowing("processlist");
            // get privileged processes
            ParsePrivileged(reader);

            Dictionary<string, string> eventDict;
            // read to eventlist
            reader.ReadToFollowing("eventlist");
            // iterate over events
            while (reader.ReadToFollowing("event")) 
            {
                // deserialize event subtree into dictionary<string,string>
                eventDict = deserializeSubtreeEvent(reader);

                // check event against indicator entries and add to findings
                checkEvent(eventDict);

                eventDict = null; // does c# garabage collector need this? how do I get shit off my stack lol
            }
        }

        void PrintFindings()
        {
            foreach (Tuple<string,Dictionary<string,string>> find in findings)
            {
                // context entry
                if (find.Item1.StartsWith("$")) { continue; }

                // https://stackoverflow.com/a/3871782/11567632 
                Console.WriteLine(find.Item1 + ":\n" + string.Join(";", find.Item2.Select(x => x.Key + "=" + x.Value).ToArray()) +"\n");
                // TODO: better print format
            }
        }

        // Usage: ProcVuln [Log.xml path]
        static void Main(string[] args)
        {
            ProcVuln run = new ProcVuln(args[0], args[1]);
            run.Parser();
            run.PrintFindings();

            Console.ReadKey(); // just for degbugging
        }
    }
}
