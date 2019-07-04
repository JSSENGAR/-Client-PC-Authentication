using System;
using System.Web.UI;
using System.Data.SqlClient;
using System.Web;
using System.Management;
using System.Management.Instrumentation;
using System.Net.NetworkInformation;
using System.Collections.Generic;
using System.Linq;
using System.Web.UI.WebControls;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.IO;
using System.Globalization;
using System.Security.Cryptography;

namespace SAP
{
    public partial class SSL : System.Web.UI.Page
    {

        [DllImport("Iphlpapi.dll")]
        private static extern int SendARP(Int32 dest, Int32 host, ref Int64 mac, ref Int32 length);
        [DllImport("Ws2_32.dll")]
        private static extern Int32 inet_addr(string ip);
        
		protected void Page_Load(object sender, EventArgs e)
        {
            //try
            //{
            Session["ConString"] = "";
            Session["usys"] = HttpContext.Current.Request.Url.PathAndQuery;
            Session["ahost"] = HttpContext.Current.Request.Url.Host;
              //Response.Write("<br/> A." + System.Net.Dns.GetHostName());            
              //Response.Write("<br/> 1." + ConS);            
              //Response.Write("<br/> 2." + Session["ahost"].ToString());
              //Response.Write("<br/> 3." + HttpContext.Current.Session["tenant"]);
              //Response.Write("<br/> 2." + HttpContext.Current.Request.Url.Host);
              //Response.Write("<br/> 2." + HttpContext.Current.Request.Url.Authority);
              //Response.Write("<br/> 3." + HttpContext.Current.Request.Url.Port);
              //Response.Write("<br/> 4." + HttpContext.Current.Request.Url.AbsolutePath);
              //Response.Write("<br/> 5." + HttpContext.Current.Request.ApplicationPath);
              //Response.Write("<br/> 6." + HttpContext.Current.Request.Url.AbsoluteUri);
                //Response.Write("<br/> 7." + HttpContext.Current.Request.Url.PathAndQuery);
              //Response.Write(System.DateTime.Today.Date);            
              //Response.Write(HttpContext.Current.Request.Url.LocalPath);

              //Response.Write(Session["uip"].ToString());
              //Response.Write(o.CC());

              string[] computer_name = System.Net.Dns.GetHostEntry(Request.ServerVariables["remote_addr"]).HostName.Split(new Char[] { '.' });
              String ecn = System.Environment.MachineName;
              // txtECN.Text = System.Net.Dns.GetHostEntry(Request.ServerVariables["REMOTE_HOST"]).HostName;
              Response.Write("<br/> A." + System.Net.Dns.GetHostEntry(Request.ServerVariables["REMOTE_HOST"]).HostName);
              Response.Write("<br/> B. UserHostAddress " + System.Web.HttpContext.Current.Request.UserHostAddress);
              Response.Write("<br/> C. LogonUserIdentity " + System.Web.HttpContext.Current.Request.LogonUserIdentity);
              Response.Write("<br/> D. UserAgent " + System.Web.HttpContext.Current.Request.UserAgent);
              Response.Write("<br/> E. UserHostName " + System.Web.HttpContext.Current.Request.UserHostName);
              Response.Write("<br/> F. UserLanguages " + System.Web.HttpContext.Current.Request.UserLanguages);
              Response.Write("<br/> G. AnonymousID " + System.Web.HttpContext.Current.Request.AnonymousID);
              Response.Write("<br/> H. ClientCertificate " + System.Web.HttpContext.Current.Request.ClientCertificate);
              Response.Write("<br/> I. ContentEncoding " + System.Web.HttpContext.Current.Request.ContentEncoding);
              Response.Write("<br/> J. ContentLength " + System.Web.HttpContext.Current.Request.ContentLength);
              Response.Write("<br/> K. ContentType " + System.Web.HttpContext.Current.Request.ContentType);
              Response.Write("<br/> L. Cookies " + System.Web.HttpContext.Current.Request.Cookies);
              Response.Write("<br/> M. CurrentExecutionFilePath " + System.Web.HttpContext.Current.Request.CurrentExecutionFilePath);
              Response.Write("<br/> N. CurrentExecutionFilePathExtension " + System.Web.HttpContext.Current.Request.CurrentExecutionFilePathExtension);
              Response.Write("<br/> O. FilePath " + System.Web.HttpContext.Current.Request.FilePath);
              Response.Write("<br/> P. Files " + System.Web.HttpContext.Current.Request.Files);
              Response.Write("<br/> Q. Filter " + System.Web.HttpContext.Current.Request.Filter);
              Response.Write("<br/> R. Form " + System.Web.HttpContext.Current.Request.Form);
              Response.Write("<br/> S. GetBufferedInputStream " + System.Web.HttpContext.Current.Request.GetBufferedInputStream());
              Response.Write("<br/> T. GetHashCode " + System.Web.HttpContext.Current.Request.GetHashCode());
              Response.Write("<br/> T0. AcceptTypes " + System.Web.HttpContext.Current.Request.AcceptTypes);
              Response.Write("<br/> T1. AnonymousID " + System.Web.HttpContext.Current.Request.AnonymousID);            
              Response.Write("<br/> U. Subject " + System.Web.HttpContext.Current.Request.ClientCertificate.Subject);
              Response.Write("<br/> U0. SerialNumber " + System.Web.HttpContext.Current.Request.ClientCertificate.SerialNumber);
              Response.Write("<br/> U1. PublicKey " + System.Web.HttpContext.Current.Request.ClientCertificate.PublicKey);            
              Response.Write("<br/> V. Headers " + System.Web.HttpContext.Current.Request.Headers);
              Response.Write("<br/> W. UrlReferrer " + System.Web.HttpContext.Current.Request.UrlReferrer);
              Response.Write("<br/> X. url " + System.Web.HttpContext.Current.Request.Url.UserInfo);
              Response.Write("<br/> X0. url " + System.Web.HttpContext.Current.Request.Url.UserEscaped);
              Response.Write("<br/> X1. HostName " + System.Net.Dns.GetHostEntry(Request.ServerVariables["REMOTE_HOST"]).HostName);
              Response.Write("<br/> X2. Address list " + System.Net.Dns.GetHostEntry(Request.ServerVariables["REMOTE_HOST"]).AddressList);
              Response.Write("<br/> X3. MAC Address " + o.GetMACAddress());
              Response.Write("<br/> X3. MAC Address " + Convert.ToString(Guid.NewGuid()));
              Response.Write("<br/> X3. MAC Address1 " + o.GetMACAddress1());
              Response.Write("<br/> X3. MAC Address3 " + o.GetMacAddress3());
              //Response.Write("<br/> X3. MAC Address4 " + o.GetMACAddress4());
              Response.Write("<br/> X3. MAC Address5 " + o.GetMACAddress5());
              //$computerId = SERVER['HTTP_USER_AGENT'].SERVER['LOCAL_ADDR'].SERVER['LOCAL_PORT'].SERVER['REMOTE_ADDR'];

              Response.Write("<br/> Y. TimedOutToken " + System.Web.HttpContext.Current.Request.TimedOutToken);
              Response.Write("<br/> Z. PhysicalPath " + System.Web.HttpContext.Current.Request.PhysicalPath);
              Response.Write("<br/> 0. PhysicalApplicationPath " + System.Web.HttpContext.Current.Request.PhysicalApplicationPath);
              //Response.Write("<br/> 1. Params " + System.Web.HttpContext.Current.Request.Params);
              Response.Write("<br/> 2. Path " + System.Web.HttpContext.Current.Request.Path);
              Response.Write("<br/> 3. PathInfo " + System.Web.HttpContext.Current.Request.PathInfo);


              string mac = "";
              foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
              {

                  if (nic.OperationalStatus == OperationalStatus.Up && (!nic.Description.Contains("Virtual") && !nic.Description.Contains("Pseudo")))
                  {
                      if (nic.GetPhysicalAddress().ToString() != "")
                      {
                          mac = nic.GetPhysicalAddress().ToString();
                      }
                  }
              }
              Response.Write("<br/> 3. mac " + mac);








            Response.Write("<br/> A." + System.Net.Dns.GetHostName());
               Response.Write("<br/> b." + System.Web.HttpContext.Current.Request.UserHostAddress);
               Response.Write("<br/> c. MachineName - " + Environment.MachineName.ToString());
               Response.Write("<br/> d. UserDomainName - " + Environment.UserDomainName.ToString());
               Response.Write("<br/> e. UserName - " + Environment.UserName.ToString());
               Response.Write("<br/> f. OSVersion - " + Environment.OSVersion.ToString());
               Response.Write("<br/> g. CurrentManagedThreadId - " + Environment.CurrentManagedThreadId.ToString());
               Response.Write("<br/> h. GetEnvironmentVariables - " + Environment.GetEnvironmentVariables());
               Response.Write("<br/> i. GetLogicalDrives - " + Environment.GetLogicalDrives());            
               Response.Write("<br/> j. NewLine - " + Environment.NewLine.ToString());
               Response.Write("<br/> k. ProcessorCount - " + Environment.ProcessorCount.ToString());
               Response.Write("<br/> l. WorkingSet - " + Environment.WorkingSet.ToString());
               Response.Write("<br/> m. Version - " + Environment.Version.ToString());
               Response.Write("<br/> n. UserInteractive - " + Environment.UserInteractive.ToString());
               Response.Write("<br/> o. SystemDirectory - " + Environment.SystemDirectory.ToString());
               Response.Write("<br/> p. StackTrace - " + Environment.StackTrace.ToString());
               Response.Write("<br/> q. CurrentDirectory - " + Environment.CurrentDirectory.ToString());
            
               ManagementObjectSearcher mo = new ManagementObjectSearcher("select * from Win32_Processor");


               foreach (ManagementObject mob in mo.Get())

               {

                   try

                   {

                       // listBox1.Items.Add(mob["ProcessorId"].ToString());
                       Response.Write(mob["ProcessorId"].ToString());


                   }

                   catch (Exception ex)

                   {

                       // handle exception

                   }

               }*/

        }

        protected void Button1_Click(object sender, EventArgs e)
        {
            // try
            //{
            string userip = HttpContext.Current.Request.UserHostAddress;
            string strClientIP = HttpContext.Current.Request.UserHostAddress.ToString().Trim();
            Int32 ldest = inet_addr(strClientIP);
            Int32 lhost = inet_addr("");
            Int64 macinfo = new Int64();
            Int32 len = 6;
            int res = SendARP(ldest, 0, ref macinfo, ref len);
            string mac_src = macinfo.ToString("X");
            if (mac_src == "0")
            {
                if (userip == "127.0.0.1")
                    HttpContext.Current.Response.Write("visited Localhost!");
                else
                    HttpContext.Current.Response.Write("the IP from" + userip + "" + "<br>");
                return;
            }

            while (mac_src.Length < 12)
            {
                mac_src = mac_src.Insert(0, "0");
            }

            string mac_dest = "";

            for (int i = 0; i < 11; i++)
            {
                if (0 == (i % 2))
                {
                    if (i == 10)
                    {
                        mac_dest = mac_dest.Insert(0, mac_src.Substring(i, 2));
                    }
                    else
                    {
                        mac_dest = "-" + mac_dest.Insert(0, mac_src.Substring(i, 2));
                    }
                }
            }

            // HttpContext.Current.Response.Write("welcome" + userip + "<br>" + ", the mac address is" + mac_dest + "." + "<br>");


            SqlDataReader sdr, sdrssy;
            int syear = 0;
            con.Open();
            string cct = "$";
            //try
            //{
            cct = o.CC();
            /*}
            catch
            {
                cct = "";
            }*/

            //if (o.C_Name("LR") == "Y" &&  (cct == "IN" || cct=="") && atmp<3)
            string cook="0";
            try
            {
                cook = Request.Cookies["igasjdhfka"].Value;
            }
            catch
            {                
                string guid = Convert.ToString(Guid.NewGuid());
                Response.Cookies["igasjdhfka"].Value = guid;
                Response.Cookies["igasjdhfka"].Expires = DateTime.Now.AddDays(365);
            }


            if (Request.Cookies["igasjdhfka"].Value != null)
            {

                int bt = Convert.ToInt32(o.C_Name("aaftr")) + 1;
                
                string pcn = "";
                try
                {
                    pcn = System.Net.Dns.GetHostEntry(Request.ServerVariables["REMOTE_HOST"]).HostName;
                }
                catch (Exception ex)
                {
                    pcn = ex.Message;
                }

                SqlCommand cmdpci = new SqlCommand("select top 1 RS from TSL where Tenant='" + Session["tenant"].ToString() + "' and PCN='" + pcn + "' and IP='" + ipo.IP2Long(Session["uip"].ToString()) + "' and GUIdgD='" + Request.Cookies["igasjdhfka"].Value + "' and MACID='" + mac_dest + "' order by dt desc", con);
                SqlDataReader sdrpci = cmdpci.ExecuteReader();
                if (sdrpci.HasRows)
                {
                    sdrpci.Close();

                    if (o.C_Name("LR") == "Y" && o.CC() == "IN" && Convert.ToInt32(Label2.Text) < Convert.ToInt32(o.C_Name("aatmp")) && (bt > Convert.ToInt32(o.C_Name("aaftr"))))
                    {
                
                        if (sdr.HasRows && sdr["AccStat"].ToString() == "1" && TextBox1.Text == sdr["User_Id"].ToString() && TextBox2.Text == o.Decrypt(sdr["Password"].ToString()))
                        {
                                        Response.Redirect("~/HOME.aspx?User_Name=" + Session["User_Name"].ToString() + "&User_right=" + Session["User_right"].ToString() + "&sess=" + Session["sess"].ToString());                
                        }
                        else
                        {
                            Label1.Text = "Unauthorized Access, if authorized please insert correct user id & password with assign right";                            
                        }
                    }
                }
                sdrpci.Close();
            }
            con.Close();
            }
        public void inspcatt(string mac_dest)
        {
            SqlCommand cmdpci = new SqlCommand("select top 1 RS from TSLinfo where Tenant='" + Session["tenant"].ToString() + "' and IP='" + ipo.IP2Long(Session["uip"].ToString()) + "' and GUID='" + Request.Cookies["igasjdhfka"].Value + "' and MACID='" + mac_dest + "' order by dt desc", con);
            SqlDataReader sdrpci = cmdpci.ExecuteReader();
            if (sdrpci.HasRows)
            {
                sdrpci.Read();
                if (sdrpci["RS"].ToString() == "2")
                {
                    //ClientScript.RegisterStartupScript(this.GetType(), "alert", "alert('Blocked')", true);
                    //ClientScript.RegisterStartupScript(this.GetType(), "alert", "alert('Unauthorized access  !!')", true);
                    Label1.Text = "Blocked";
                }
                else if (sdrpci["RS"].ToString() == "0")
                {
                    //ClientScript.RegisterStartupScript(this.GetType(), "alert", "alert('Your request is in process..')", true);
                    Label1.Text = "Your request is in process..";
                }

            }
            else
            {
                sdrpci.Close();
                Response.Cookies["idjhjgugu"].Values.Clear();
                string guid = Convert.ToString(Guid.NewGuid());
                Response.Cookies["idjhjgugu"].Value = guid;
                Response.Cookies["idjhjgugu"].Expires = DateTime.Now.AddDays(365);                
            }
            sdrpci.Close();
        }
        
		private string getUniqueID(string drive)
        {
            if (drive == string.Empty)
            {
                //Find first drive
                foreach (DriveInfo compDrive in DriveInfo.GetDrives())
                {
                    if (compDrive.IsReady)
                    {
                        drive = compDrive.RootDirectory.ToString();
                        break;
                    }
                }
            }

            if (drive.EndsWith(":\\"))
            {
                //C:\ -> C
                drive = drive.Substring(0, drive.Length - 2);
            }

            string volumeSerial = getVolumeSerial(drive);
            string cpuID = getCPUID();

            //Mix them up and remove some useless 0's
            return cpuID.Substring(13) + cpuID.Substring(1, 4) + volumeSerial + cpuID.Substring(4, 4);
        }

        private string getVolumeSerial(string drive)
        {
            ManagementObject disk = new ManagementObject(@"win32_logicaldisk.deviceid=""" + drive + @":""");
            disk.Get();

            string volumeSerial = disk["VolumeSerialNumber"].ToString();
            disk.Dispose();

            return volumeSerial;
        }

        private string getCPUID()
        {
            string cpuInfo = "";
            ManagementClass managClass = new ManagementClass("win32_processor");
            ManagementObjectCollection managCollec = managClass.GetInstances();

            foreach (ManagementObject managObj in managCollec)
            {
                if (cpuInfo == "")
                {
                    //Get only the first CPU's ID
                    cpuInfo = managObj.Properties["processorID"].Value.ToString();
                    break;
                }
            }

            return cpuInfo;
        }


        private static string _fingerPrint = string.Empty;
        private static string Value()
        {
            //You don't need to generate the HWID again if it has already been generated. This is better for performance
            //Also, your HWID generally doesn't change when your computer is turned on but it can happen.
            //It's up to you if you want to keep generating a HWID or not if the function is called.
            if (string.IsNullOrEmpty(_fingerPrint))
            {
                _fingerPrint = GetHash("CPU >> " + CpuId() + "\nBIOS >> " + BiosId() + "\nBASE >> " + BaseId() + "\nDISK >> " + DiskId() + "\nVIDEO >> " + VideoId() + "\nMAC >> " + MacId());
            }
            return _fingerPrint;
        }
        private static string GetHash(string s)
        {
            //Initialize a new MD5 Crypto Service Provider in order to generate a hash
            MD5 sec = new MD5CryptoServiceProvider();
            //Grab the bytes of the variable 's'
            byte[] bt = Encoding.ASCII.GetBytes(s);
            //Grab the Hexadecimal value of the MD5 hash
            return GetHexString(sec.ComputeHash(bt));
        }

        private static string GetHexString(IList<byte> bt)
        {
            string s = string.Empty;
            for (int i = 0; i < bt.Count; i++)
            {
                byte b = bt[i];
                int n = b;
                int n1 = n & 15;
                int n2 = (n >> 4) & 15;
                if (n2 > 9)
                    s += ((char)(n2 - 10 + 'A')).ToString(CultureInfo.InvariantCulture);
                else
                    s += n2.ToString(CultureInfo.InvariantCulture);
                if (n1 > 9)
                    s += ((char)(n1 - 10 + 'A')).ToString(CultureInfo.InvariantCulture);
                else
                    s += n1.ToString(CultureInfo.InvariantCulture);
                if ((i + 1) != bt.Count && (i + 1) % 2 == 0) s += "-";
            }
            return s;
        }

        //Return a hardware identifier
        private static string Identifier(string wmiClass, string wmiProperty, string wmiMustBeTrue)
        {
            string result = "";
            System.Management.ManagementClass mc = new System.Management.ManagementClass(wmiClass);
            System.Management.ManagementObjectCollection moc = mc.GetInstances();
            foreach (System.Management.ManagementBaseObject mo in moc)
            {
                if (mo[wmiMustBeTrue].ToString() != "True") continue;
                //Only get the first one
                if (result != "") continue;
                try
                {
                    result = mo[wmiProperty].ToString();
                    break;
                }
                catch
                {
                }
            }
            return result;
        }
        //Return a hardware identifier
        private static string Identifier(string wmiClass, string wmiProperty)
        {
            string result = "";
            System.Management.ManagementClass mc = new System.Management.ManagementClass(wmiClass);
            System.Management.ManagementObjectCollection moc = mc.GetInstances();
            foreach (System.Management.ManagementBaseObject mo in moc)
            {
                //Only get the first one
                if (result != "") continue;
                try
                {
                    result = mo[wmiProperty].ToString();
                    break;
                }
                catch
                {
                }
            }
            return result;
        }
        private static string CpuId()
        {
            //Uses first CPU identifier available in order of preference
            //Don't get all identifiers, as it is very time consuming
            string retVal = Identifier("Win32_Processor", "UniqueId");
            if (retVal != "") return retVal;
            retVal = Identifier("Win32_Processor", "ProcessorId");
            if (retVal != "") return retVal;
            retVal = Identifier("Win32_Processor", "Name");
            if (retVal == "") //If no Name, use Manufacturer
            {
                retVal = Identifier("Win32_Processor", "Manufacturer");
            }
            //Add clock speed for extra security
            retVal += Identifier("Win32_Processor", "MaxClockSpeed");
            return retVal;
        }
        //BIOS Identifier
        private static string BiosId()
        {
            return Identifier("Win32_BIOS", "Manufacturer") + Identifier("Win32_BIOS", "SMBIOSBIOSVersion") + Identifier("Win32_BIOS", "IdentificationCode") + Identifier("Win32_BIOS", "SerialNumber") + Identifier("Win32_BIOS", "ReleaseDate") + Identifier("Win32_BIOS", "Version");
        }
        //Main physical hard drive ID
        private static string DiskId()
        {
            return Identifier("Win32_DiskDrive", "Model") + Identifier("Win32_DiskDrive", "Manufacturer") + Identifier("Win32_DiskDrive", "Signature") + Identifier("Win32_DiskDrive", "TotalHeads");
        }
        //Motherboard ID
        private static string BaseId()
        {
            return Identifier("Win32_BaseBoard", "Model") + Identifier("Win32_BaseBoard", "Manufacturer") + Identifier("Win32_BaseBoard", "Name") + Identifier("Win32_BaseBoard", "SerialNumber");
        }
        //Primary video controller ID
        private static string VideoId()
        {
            return Identifier("Win32_VideoController", "DriverVersion") + Identifier("Win32_VideoController", "Name");
        }
        //First enabled network card ID
        private static string MacId()
        {
            return Identifier("Win32_NetworkAdapterConfiguration", "MACAddress", "IPEnabled");
        }
    }
}