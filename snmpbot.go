package main


import (
  "fmt"
  "log"
  "os"
  "os/exec"
  "strings"
  "bytes"
  "strconv"
  "errors"
  "time"
  "net/http"
  "encoding/json"
  "encoding/csv"
  
)
const alert1 = "Host is Unreachable"
const alert2 = "Syslog-ng is Unreachable"
const alert3 = "Logstash is Unreachable"
const alert4 = "Elasticsearch is Unreachable"
const alert5 = "SSH is Unreachable"
const alert6 = "Memory usage is high (>80%)"
const alert6Point1 = "Memory usage is Critical (>90%)"
const alert7 = "CPU usage is high (>80%)"
const alert7Point1 = "CPU usage is Critical (>90%)"
const alert9 = "Root - Disk Free Low (<10%)"
const alert10 = "Storage - Disk Free Low (<10%)"
const warnThreashSCpu int = 80
const critThreashSCpu int = 90
const warnThreashSMem int = 90
const critThreashSMem int = 95
var critThreashRoot int = 90
const critThreashStorage int = 95


type sendMessageReqBody struct {
  ChatID int64  `json:"chat_id"`
  Text   string `json:"text"`
}


func main() {
  // Open the file
  csvfile, err := os.Open("gofetch.conf")
  if err != nil {
    log.Fatalln("Couldn't open the coonfiguration file ", err)
  }


  
  for {
    // Parse the file
    r := csv.NewReader(csvfile)
    record, _ := r.ReadAll()
    if err != nil {
      log.Fatal(err)
    }
    client_pool := (len(record))
    for i := 0; i < client_pool; i++ {
      clientCall(record[i][0],record[i][1], record[i][2], record[i][3])
    }
    fmt.Println("Executuing time")
    time.Sleep(60 * time.Second)
  }
  


}
func clientCall(clientName string,clientIP string,snmpPort string, secret string) {
  /// Setting variables from 
  oid := ".1.3.6.1.4.1.8072.1.3.2.3.1.2.13.47.117.115.114.47.98.105.110.47.98.97.115.104"
  clientIPWithPort0 := []string{clientIP,snmpPort}
  clientIPWithPort := strings.Join(clientIPWithPort0[:], ":")
  /// Checking Status of Host 
  statusCheck := []string{"snmpget -v 2c -c ", secret,"-O e ",clientIPWithPort, oid,  "2> /dev/null 1>/dev/null", ";" ,"echo $?"};
  statusCheckString := strings.Join(statusCheck[:], " ")
  statusCheckCmd := exec.Command("bash","-c",statusCheckString)
  var outA, errA bytes.Buffer
  statusCheckCmd.Stdout = &outA
  statusCheckCmd.Stderr = &errA
  errStatusCheck := statusCheckCmd.Run()
  if errStatusCheck != nil {
    fmt.Println(errStatusCheck)
  }
  statusCheck_01 := strings.Split(outA.String(),"\n")
  i, _:= strconv.Atoi(statusCheck_01[0])
  
  /// Conditional Statement for validating Host status check. If host is not reachable 
  /// the following code will Invoking alert function and skip the rest of the code
  if i==1 {
    //generate alert function 
    // genAlert(clientIP,"Unrechable")
    broadcast2Telegram(clientName,alert1)
    fmt.Println(clientIP,"is unreachable\nInvoking Alert Funciton")
    
    


  } else {
    // Calling monitoring script with SNMP Command
    //Organizing the SNMP command


    command := []string{"snmpwalk", "-v", "2c", "-c", secret, "-O" , "e", clientIPWithPort, oid,"|", "paste -s -d ','","|", "cut -d ',' -f 2-"};
    cmdString := strings.Join(command[:], " ")
    snmpCommand := exec.Command("bash","-c",cmdString)


    //Invoking the SNMP Command and keep values to buffer
    var outB, errB bytes.Buffer
    snmpCommand.Stdout = &outB
    snmpCommand.Stderr = &errB
    errSnmpCommand := snmpCommand.Run()
    if errSnmpCommand != nil {
      fmt.Println(errSnmpCommand)
      return
    }
    // Converting buffer to []string literals for the sake of escallationJudge function
    snmpCmdOutput := strings.Split(outB.String(),"\n")
    //fmt.Println(snmpCmdOutput[0])
    // Feeding the converted value to escallationJudge function
    escallationJudge(clientName, snmpCmdOutput)


    // Writting snmpCmdOutput to a file
    
    //Creating file name [clientIP +.log]
    outputFileName := []string{clientIP, ".log"};
    outputFileNameStr := strings.Join(outputFileName[:], "")

    outfile, err := os.OpenFile(outputFileNameStr,  os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {      fmt.Println(err)    } 
   // Trimming buffered snmpCommandOutput to byte    
 	prefix := bytes.TrimRight(outB.Bytes(), "\r")
    defer outfile.Close()
    // Writting the new converted byte.buffer to the file    _, err2 := outfile.Write(prefix)    if err2 != nil {      fmt.Println(err2)    }  }} 
func escallationJudge(clientName string, input []string) {
	    var intFields, stringFields = mapField(input)  
	    // Alert description  //var alert1 = "Host is Unreachable"
  // Starting conditional checking   
if stringFields["syslog-ng"] == "inactive" {        
	// Invoking alert function   
	broadcast2Telegram(clientName,alert2)  }   
	if stringFields["logstash"] == "inactive" {        
		// Invoking alert function    
		broadcast2Telegram(clientName,alert3)  
		}  
	if stringFields["elasticsearch"] == "inactive" { 
	       // Invoking alert function    
		broadcast2Telegram(clientName,alert4)  
		}  
	if stringFields["sshd"] == "inactive" { 
		// Invoking alert function    b
		roadcast2Telegram(clientName,alert5)  
		}
	if intFields["cpuUsgPcnt"] > warnThreashSCpu {        
		// Invoking alert function    
		broadcast2Telegram(clientName,alert7)  
		}  
	if intFields["cpuUsgPcnt"] > critThreashSCpu {    
		// Invoking alert function    
		broadcast2Telegram(clientName,alert7Point1)  
		}  
	if intFields["memUsgPcnt"] > warnThreashSMem {    
		// Invoking alert function            
	broadcast2Telegram(clientName,alert6)  
	}   
	if intFields["memUsgPcnt"] > critThreashSMem {    
		// Invoking alert function            
		broadcast2Telegram(clientName,alert6Point1)  
		}  
	if intFields["diskUsgPcntRoot"]  > critThreashRoot {
		    // Invoking alert function    
		broadcast2Telegram(clientName,alert9)  }  
	if intFields["diskUsgPcntStorage"] > critThreashStorage {    
		// Invoking alert function            
		broadcast2Telegram(clientName,alert10)  
		}     //fmt.Println(intFields,"\n",stringFields)
}
func mapField(snmpCmdOutput []string) (map[string]int,map[string]string) { 
	 // Spliting the Index 0 of the CSV input   
	inputFields := strings.Split(snmpCmdOutput[0], ",")  
  // Creating two types of Maps. One for String type another for Int type  
	var mString = make(map[string]string)  var mInt = make(map[string]int)
  // Mapping the field name with inputFields
    mString["timeStamp"] = inputFields[0]  
	mString["hostName"] = inputFields[1]  
	mString["syslog-ng"] = inputFields[2]  
	mString["elasticsearch"] = inputFields[3]  
	mString["logstash"] = inputFields[4]  
	mString["sshd"] = inputFields[5]    
	mInt["memUsgPcnt"], _= strconv.Atoi(inputFields[6])  
	mInt["cpuUsgPcnt"], _= strconv.Atoi(inputFields[7])  
	mInt["upitme"], _= strconv.Atoi(inputFields[8]) 
	mInt["diskUsgPcntRoot"], _= strconv.Atoi(inputFields[9])  
	mInt["diskUsgPcntStorage"], _= strconv.Atoi(inputFields[10])    
	return mInt,mString
}


func broadcast2Telegram(hostName string,alert string) error {
	// Create the request body 
	struct  var chatID int64 = -483332909  
	longtext := []string{"Host: ",hostName,"\n",alert}  
	longtextString := strings.Join(longtext[:], "")    
	reqBody := &sendMessageReqBody{    ChatID: chatID,    Text:   longtextString,  }
	  // Create the JSON body from the 
	struct  reqBytes, err := json.Marshal(reqBody)  
	if err != nil {    
		return err  
	}
  // Send a post request with your token  
	res, err := http.Post("https://api.telegram.org/bot666:blabla/sendMessage", "application/json", bytes.NewBuffer(reqBytes)) 
	if err != nil {    
		return err  
	}  
	if res.StatusCode != http.StatusOK {
		return errors.New("unexpected status" + res.Status)  
	}
  return nil
}

