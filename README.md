```
<form version="1.1" theme="dark">
  <label>Windows Event Collection - Logon and Failed Attempts</label>
  <description>Dashboard to identify non-administrative logons to servers and detect failed logon attempts due to incorrect passwords.</description>
  <fieldset submitButton="false" autoRun="true">
    <input type="text" token="computername" searchWhenChanged="true">
      <label>Computer Name (FQDN)</label>
      <default>*</default>
      <initialValue>*</initialValue>
    </input>
    <input type="text" token="workstationname" searchWhenChanged="true">
      <label>Workstation Name</label>
      <default>*</default>
      <initialValue>*</initialValue>
    </input>
    <input type="text" token="sourcenetworkaddress" searchWhenChanged="true">
      <label>Source Network Address</label>
      <default>*</default>
      <initialValue>*</initialValue>
    </input>
    <input type="text" token="username" searchWhenChanged="true">
      <label>Username</label>
      <default>*</default>
      <initialValue>*</initialValue>
    </input>
    <input type="dropdown" token="logontype" searchWhenChanged="true">
      <label>Logon Type</label>
      <choice value="Logon_Type=1">Interactive</choice>
      <choice value="Logon_Type=2">Network</choice>
      <choice value="Logon_Type=3">Batch</choice>
      <choice value="Logon_Type=4">Service</choice>
      <choice value="Logon_Type=5">Unlock</choice>
      <choice value="Logon_Type=6">Network_Cleartext</choice>
      <choice value="Logon_Type=7">New Account</choice>
      <choice value="Logon_Type=8">Remote Interactive</choice>
      <choice value="Logon_Type=9">Cached Interactive</choice>
      <default>*</default>
      <initialValue>*</initialValue>
    </input>
    <input type="time" token="time" searchWhenChanged="true">
      <label>Time Range</label>
      <default>
        <earliest>-24h@h</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>
  <row>
    <panel>
      <single>
        <title>User Login Success Rate</title>
        <search>
          <query>
          index="windows_server" (EventCode=4624 OR EventCode=4625)
          | eval Result=if(EventCode=4624, "Successful", "Failed")
          | stats count by Result
          | eval Rate=round((count / sum(count)) * 100, 2)
        </query>
          <earliest>$time.earliest$</earliest>
          <latest>$time.latest$</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="rangeColors">["0x53a051","0x0877a6","0xf8be34","0xf1813f","0xdc4e41"]</option>
        <option name="useColors">1</option>
      </single>
    </panel>
    <panel>
      <table>
        <title>Domain Statistics</title>
        <search>
          <query>index="windows_server" EventCode=4624 NOT (
              Source_Network_Address="-"
              OR Logon_Process="NtLmSsp"
              OR Account_Name="$*"
              OR Account_Name="ANONYMOUS LOGON"
              OR Account_Name="adm*"
            ) 
            | regex Account_Name!="\$$"
            | eval LogonType=case(
              Logon_Type == 1,"Interactive",
              Logon_Type == 2,"Network",
              Logon_Type == 3,"Batch",
              Logon_Type == 4,"Service",
              Logon_Type == 5,"Unlock",
              Logon_Type == 6,"Network_Cleartext",
              Logon_Type == 7,"New Account",
              Logon_Type == 8,"Remote Interactive",
              Logon_Type == 9,"Cached Interactive"
            )
            | rename Keywords AS Status
            | search ComputerName=$computername$ Workstation_Name=$workstationname$ Source_Network_Address=$sourcenetworkaddress$ LogonType=$logontype$ Account_Name=$username$ Account_Domain="galaxydt.vn"
            | stats count(Account_Name) as count by Account_Domain
            | sort - count</query>
          <earliest>$time.earliest$</earliest>
          <latest>$time.latest$</latest>
          <refresh>30s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">none</option>
        <option name="refresh.display">progressbar</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <single>
        <title>Total Users Created</title>
        <search>
          <query>
          index="windows_server" EventCode=4720
          | stats count as "Total Users Created"
        </query>
          <earliest>$time.earliest$</earliest>
          <latest>$time.latest$</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="rangeColors">["0x53a051","0x53a051","0x53a051","0x53a051","0x53a051"]</option>
        <option name="useColors">1</option>
      </single>
    </panel>
    <panel>
      <single>
        <title>Total Users Deleted</title>
        <search>
          <query>
          index="windows_server" EventCode=4726
          | stats count as "Total Users Deleted"
        </query>
          <earliest>$time.earliest$</earliest>
          <latest>$time.latest$</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="rangeColors">["0xdc4e41","0xdc4e41","0xdc4e41","0xdc4e41","0xdc4e41"]</option>
        <option name="useColors">1</option>
      </single>
    </panel>
    <panel>
      <single>
        <title>Total Users Updated</title>
        <search>
          <query>
          index="windows_server" EventCode=4722
          | stats count as "Total Users Updated"
        </query>
          <earliest>$time.earliest$</earliest>
          <latest>$time.latest$</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="rangeColors">["0x53a051","0xf8be34","0xf8be34","0xf8be34","0xdc4e41"]</option>
        <option name="useColors">1</option>
      </single>
    </panel>
    <panel>
      <single>
        <title>Total Users Disabled</title>
        <search>
          <query>
          index="windows_server" EventCode=4725
          | stats count as "Total Users Disabled"
        </query>
          <earliest>$time.earliest$</earliest>
          <latest>$time.latest$</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="rangeColors">["0xf1813f","0xf1813f","0xf1813f","0xf1813f","0xf1813f"]</option>
        <option name="useColors">1</option>
      </single>
    </panel>
    <panel>
      <single>
        <title>Total Users Locked</title>
        <search>
          <query>
          index="windows_server" EventCode=4740
          | stats count as "Total Users Locked"
        </query>
          <earliest>$time.earliest$</earliest>
          <latest>$time.latest$</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="rangeColors">["0x555","0x555","0x555","0x555","0x555"]</option>
        <option name="useColors">1</option>
      </single>
    </panel>
    <panel>
      <single>
        <title>Total Users Enabled</title>
        <search>
          <query>
          index="windows_server" EventCode=4722
          | stats count as "Total Users Enabled"
        </query>
          <earliest>$time.earliest$</earliest>
          <latest>$time.latest$</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="rangeColors">["0x53a051","0x0877a6","0xf8be34","0xf1813f","0xdc4e41"]</option>
        <option name="useColors">1</option>
      </single>
    </panel>
    <panel>
      <single>
        <title>Total Events</title>
        <search>
          <query>
          index="windows_server"
          | stats count as "Total Events"
        </query>
          <earliest>$time.earliest$</earliest>
          <latest>$time.latest$</latest>
        </search>
        <option name="drilldown">none</option>
      </single>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Top Failed Login Sources</title>
        <search>
          <query>
          index="windows_server" EventCode=4625
          | stats count by Source_Network_Address
          | sort -count
          | head 10
        </query>
          <earliest>$time.earliest$</earliest>
          <latest>$time.latest$</latest>
        </search>
        <option name="charting.chart">column</option>
        <option name="charting.drilldown">none</option>
      </chart>
    </panel>
    <panel>
      <table>
        <title>Recent Account Lockouts</title>
        <search>
          <query>
          index="windows_server" EventCode=4740
          | table _time Account_Name
          | sort -_time
          | head 10
        </query>
          <earliest>$time.earliest$</earliest>
          <latest>$time.latest$</latest>
        </search>
        <option name="drilldown">none</option>
      </table>
    </panel>
    <panel>
      <chart>
        <title>Logon Type Distribution</title>
        <search>
          <query>
          index="windows_server" EventCode=4624
          | stats count by Logon_Type
          | eval Logon_Type=case(
              Logon_Type==1,"Interactive",
              Logon_Type==2,"Network",
              Logon_Type==3,"Batch",
              Logon_Type==4,"Service",
              Logon_Type==5,"Unlock",
              Logon_Type==6,"Network_Cleartext",
              Logon_Type==7,"New Account",
              Logon_Type==8,"Remote Interactive",
              Logon_Type==9,"Cached Interactive"
            )
          | chart sum(count) by Logon_Type
        </query>
          <earliest>$time.earliest$</earliest>
          <latest>$time.latest$</latest>
        </search>
        <option name="charting.chart">pie</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <title>Logon Trends (Graph)</title>
        <search>
          <query>
            index="windows_server" EventCode=4624 NOT (
              Source_Network_Address="-"
              OR Logon_Process="NtLmSsp"
              OR Account_Name="$*"
              OR Account_Name="ANONYMOUS LOGON"
              OR Account_Name="adm*"
            ) 
            | regex Account_Name!="\$$"
            | eval LogonType=case(
              Logon_Type == 1,"Interactive",
              Logon_Type == 2,"Network",
              Logon_Type == 3,"Batch",
              Logon_Type == 4,"Service",
              Logon_Type == 5,"Unlock",
              Logon_Type == 6,"Network_Cleartext",
              Logon_Type == 7,"New Account",
              Logon_Type == 8,"Remote Interactive",
              Logon_Type == 9,"Cached Interactive"
            )
            | eval Account_Domain=mvindex(Account_Domain, 1)
            | eval Account_Name=mvindex(Account_Name, 1)
            | search ComputerName=$computername$ Workstation_Name=$workstationname$ Source_Network_Address=$sourcenetworkaddress$ LogonType=$logontype$ Account_Name=$username$
            | timechart span=5m count by Account_Name
          </query>
          <earliest>$time.earliest$</earliest>
          <latest>$time.latest$</latest>
          <refresh>10m</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="charting.chart">line</option>
        <option name="charting.drilldown">none</option>
        <option name="refresh.display">progressbar</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <title>Failed Logon Trends Due to Incorrect Passwords</title>
        <search>
          <query>
            index=windows* EventCode=4625 Message="*"
            | eval Account_Domain=mvindex(Account_Domain, 1)
            | eval Account_Name=mvindex(Account_Name, 1)
            | search ComputerName=$computername$ Workstation_Name=$workstationname$ Source_Network_Address=$sourcenetworkaddress$ Account_Name=$username$
            | timechart span=5m count by Account_Name
          </query>
          <earliest>$time.earliest$</earliest>
          <latest>$time.latest$</latest>
          <refresh>10m</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="charting.chart">line</option>
        <option name="charting.drilldown">none</option>
        <option name="refresh.display">progressbar</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <title>User Account Statistics</title>
        <search>
          <query>index="windows_server" EventCode=4624 NOT (
              Source_Network_Address="-"
              OR Logon_Process="NtLmSsp" 
              OR Account_Name="$*" 
              OR Account_Name="ANONYMOUS LOGON"
              OR Account_Name="adm*"
            ) 
            | regex Account_Name!="\$$"
            | eval LogonType=case(
              Logon_Type == 1,"Interactive",
              Logon_Type == 2,"Network",
              Logon_Type == 3,"Batch",
              Logon_Type == 4,"Service",
              Logon_Type == 5,"Unlock",
              Logon_Type == 6,"Network_Cleartext",
              Logon_Type == 7,"New Account",
              Logon_Type == 8,"Remote Interactive",
              Logon_Type == 9,"Cached Interactive"
            )
            | eval Account_Domain=mvindex(Account_Domain, 1)
            | eval Account_Name=mvindex(Account_Name, 1)
            | search ComputerName=$computername$ Workstation_Name=$workstationname$ Source_Network_Address=$sourcenetworkaddress$ LogonType=$logontype$ Account_Name=$username$
            | stats count(Source_Network_Address) as count by Account_Name
            | sort - count</query>
          <earliest>$time.earliest$</earliest>
          <latest>$time.latest$</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="refresh.display">progressbar</option>
      </table>
    </panel>
    <panel>
      <table>
        <title>Failed Logins by User</title>
        <search>
          <query>
            index=windows_server EventCode=4625
            | search ComputerName=$computername$ Workstation_Name=$workstationname$ Source_Network_Address=$sourcenetworkaddress$ Account_Name=$username$
            | stats count as Failed_Logins by Account_Name
            | sort - Failed_Logins
          </query>
          <earliest>$time.earliest$</earliest>
          <latest>$time.latest$</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="refresh.display">progressbar</option>
      </table>
    </panel>
  </row>
</form>
```
![image](https://github.com/user-attachments/assets/484a31bc-c8a3-42e5-94a5-2a778d60543d)
