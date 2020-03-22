using Newtonsoft.Json.Linq;
// Needs nuget system.linq
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

// TODO: dynamic context entry (Not just equals)
// TODO: blacklist functionality
// TODO: error handling for file doesn't exists, ect

// Custom Entry Properties:
// "Privileged" : "True" # Process has integrity High or System
// "PathWritable" : "True" # Path is writable by current user
// "Context" : "" # used so entries can reference others
// "Equals" : "Path" # a context property, if current entry and context entry share the same property this will be True
// "$Name" : {...} # Context entry, will not be shown in findings and can be used as Context property

namespace ProcVuln_V2
{
    class ProcVuln
    {
        string logPath;
        string indicatorPath;
        string NtAccountName;
        HashSet<string> privProcs; // best dataset for contains reference
        //Dictionary<string, Dictionary<string, string>> indicators; // holds entries from JSON file
        JObject indicators;
        List<Tuple<string, Dictionary<string, string>>> findings; // holds all possible findings with event

        ProcVuln(string lPath, string iPath, string user = null)
        {
            logPath = lPath;
            indicatorPath = iPath;
            if (user == null) {
                // TODO: Implement get current user
                NtAccountName = @"windev2001eval\user";
            }
            else { NtAccountName = user; }
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

        // XmlReader (PAY ATTENTION TO READER RETURN POSITION): https://docs.microsoft.com/en-us/dotnet/api/system.xml.xmlreader?view=netframework-4.8#methods
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

        // TODO: doesn't check group or ownership and needs admin rights to run
        // maybe just use the C function I wrote for this?
        bool checkWritable(string path)
        {
            // does not have path property
            if(path == "") {
                return false;
            }

            // https://stackoverflow.com/a/5394719/11567632
            DirectoryInfo di = new DirectoryInfo(path);
            DirectorySecurity acl = null;
            try
            {
                acl = di.GetAccessControl(AccessControlSections.All);
            }
            catch(DirectoryNotFoundException)
            {
                DirectoryInfo parentPath = di.Parent;
                if(parentPath == null) { return false; }
                return checkWritable(parentPath.FullName);
            }
            catch(UnauthorizedAccessException)
            {
                return false;
            }
            catch
            {
                // TODO: remote file checks (error 53)
                return false;
            }
            //catch(PrivilegeNotHeldException e)
            //{
            //    Console.WriteLine("[!] Needs Administrator Privilege to run.");
            //    System.Environment.Exit(1);
            //}

            AuthorizationRuleCollection rules = acl.GetAccessRules(true, true, typeof(NTAccount));

            //Go through the rules returned from the DirectorySecurity
            foreach (AuthorizationRule rule in rules)
            {
                //If we find one that matches the identity we are looking for
                if (rule.IdentityReference.Value.Equals(NtAccountName,StringComparison.CurrentCultureIgnoreCase))
                {
                    var filesystemAccessRule = (FileSystemAccessRule)rule;

                    //Cast to a FileSystemAccessRule to check for access rights
                    if ((filesystemAccessRule.FileSystemRights & FileSystemRights.WriteData)>0 && filesystemAccessRule.AccessControlType != AccessControlType.Deny)
                    {
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }
            }

            return false;
        }

        // checks context entry
        // JToken vs JObject: https://adevelopersnotes.wordpress.com/2013/11/13/json-net-jtoken-vs-jproperty-vs-jobject/
        bool checkContext(JObject props, Dictionary<string,string> eventDict)
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
            bool privileged;
            bool writablePath; 

            bool addEntry;
            string buff;

            foreach(JProperty entry in (JToken)indicators)
            {
                // TODO: refactor second loop into seperate function
                addEntry = true;
                foreach(JProperty prop in ((JObject)entry.Value).Properties())
                {
                    // check for if event was under privileged process or not (High, System)
                    if (prop.Name == "Privileged") {
                        privileged = privProcs.Contains(eventDict["Process_Name"]); // run check only if entry exists
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
                        writablePath = checkWritable(eventDict["Path"]); // run check only if entry exists
                        if(prop.Value.ToString() == writablePath.ToString()) {
                            continue;
                        }
                        else {
                            addEntry = false;
                            break;
                        }
                    }

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
                    // TODO: Add function which checks for same enteries and ignores Time_of_Day?
                    findings.Add(new Tuple<string, Dictionary<string, string>>(entry.Name,eventDict)); 
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
            // use a JSON formater for JSON file
            ProcVuln run = new ProcVuln(args[0], args[1], args[2]);
            run.Parser();
            run.PrintFindings();

            //Console.WriteLine("Done");
            Console.ReadKey(); // just for degbugging
        }
    }
}
