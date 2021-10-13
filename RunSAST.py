from ASoC import ASoC
import requests
import os
import json
import time
import zipfile
import re
import datetime
import shutil
import logging
import sys
import stat

logging.basicConfig(filename='asoc.log', format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)
logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))

class AppScanOnCloudSAST():
    asoc = None
    
    #Run SAST Scan Process
    def run(self):
        #Read Provided Variables from ENV
        scanName = os.getenv("ASOC_SCAN_NAME", "Automated Scan from asoc-sast-linux")
        apikeyid = os.getenv("ASOC_KEY")
        apikeysecret = os.getenv("ASOC_SECRET")
	
        self.targetDir = os.getenv("ASOC_TARGET_DIR")
        appid = os.getenv("ASOC_APPID")
        
        #If ASOC_WAIT = True, wait for the scan to complete
        wait = os.getenv("ASOC_WAIT", True)
        
        #Print extra info if DEBUG = True
        self.debug = os.getenv("DEBUG", False)
        
        #Run Specific Env
        repo = os.getenv("ASOC_REPO", "Not Provided")
        runNum = os.getenv("ASOC_RUN_NUMBER", "Not Provided")
        
        
        self.cwd = os.getcwd()
        self.reportDir = os.getenv("ASOC_REPORT_DIR", self.cwd)
	
        #If targetDir is not set, run from cwd
        if(self.targetDir is None):
            self.targetDir = self.cwd
        
        apikey = {
          "KeyId": apikeyid,
          "KeySecret": apikeysecret
        }
        
        self.asoc = ASoC(apikey)
        logging.info("Executing Pipe: HCL AppScan on Cloud SAST")
        logging.info("\trev 2021-08-24")
        
        #valid chars for a scan name: alphanumeric + [.-_ ]
        scanName = re.sub('[^a-zA-Z0-9\s_\-\.]', '_', scanName)+"_"+self.getTimeStamp()
        configFile = None
        comment = ""
        
        logging.info("========== Step 0: Preparation ====================")
        
        logging.info(f"Target Path [{self.targetDir}]")
        if(os.path.isdir(self.targetDir) or os.path.isfile(self.targetDir)):
            logging.info("Verified target path exists")
        else:
            logging.error("Target path does not exist!")
            return False
        
        #Create the saclient dir if it doesn not exist
        saclientPath = os.path.join(self.cwd, "saclient")
        if(not os.path.isdir(saclientPath)):
            logging.info(f"SAClient Path [{saclientPath}] does not exist")
            try:
                os.mkdir(saclientPath)
                logging.info(f"Created dir [{saclientPath}]")
            except:
                logging.error(f"Error creating saclient path [{saclientPath}]")
                self.fail("Error Running ASoC SAST Pipeline")
                return False
            if(not os.path.isdir(saclientPath)):
                logging.error(f"Error creating saclient path [{saclientPath}]")
                self.fail("Error Running ASoC SAST Pipeline")
                return False
                
        #Create Reports Dir if it does not exist 
        reportsDir = os.path.join(self.reportDir, "reports")
        if(not os.path.isdir(reportsDir)):
            logging.info(f"Reports dir doesn't exists [{reportsDir}]")
            os.mkdir(reportsDir)
            if(not os.path.isdir(reportsDir)):
                logging.error(f"Cannot create reports dir! [{reportsDir}]")
                self.fail("Error Running ASoC SAST Pipeline")
                return False
            else:
                logging.info(f"Created dir [{reportsDir}]")
                
        #Make sure we have write permission on the reports dir
        logging.info("Setting permissions on reports dir")
        result = os.system(f"chmod -R 755 {reportsDir}")
        
        if(result == 0):
            logging.info("Successfully set permissions")
        else:
            logging.error("Failed setting permissions")
            return None
            
        logging.info("========== Step 0: Complete =======================\n")
        
        #Step 1: Download the SACLientUtil
        logging.info("========== Step 1: Download SAClientUtil ==========")
        appscanPath = self.getSAClient(saclientPath)
        if(appscanPath is None):
            logging.error("AppScan Path not found, something went wrong with SACLientUtil Download?")
            self.fail("Error Running ASoC SAST Pipeline")
            return False
        logging.info("========== Step 1: Complete =======================\n")
        
        
        #Step 2: Generate the IRX
        logging.info("========== Step 2: Generate IRX File ==============")
        
        irxPath = self.genIrx(scanName, appscanPath, self.targetDir, reportsDir, configFile)
        if(irxPath is None):
            logging.error("IRX File Not Generated.")
            self.fail("Error Running ASoC SAST Pipeline")
            return False
        logging.info("========== Step 2: Complete =======================\n")
        
        
        #Step 3: Run the Scan
        logging.info("========== Step 3: Run the Scan on ASoC ===========")
        scanId = self.runScan(scanName, appid, irxPath, comment, True)
        if(scanId is None):
            logging.error("Error creating scan")
            self.fail("Error Running ASoC SAST Pipeline")
            return False
        logging.info("========== Step 3: Complete =======================\n")
        
        if(wait == False):
            self.success("ASoC SAST Pipeline Complete")
            return True
        
        #Step 4: Get the Scan Summary
        logging.info("========== Step 4: Fetch Scan Summary =============")      
        summaryFileName = scanName+".json"
        summaryPath = os.path.join(reportsDir, summaryFileName)
        logging.info("Fetching Scan Summary")
        summary = self.getScanSummary(scanId, summaryPath)
        if(summary is None):
            logging.error("Error getting scan summary")
        else:
            seconds = summary["duration_seconds"] % (24 * 3600)
            hour = seconds // 3600
            seconds %= 3600
            minutes = seconds // 60
            seconds %= 60
            durationStr = "%d:%02d:%02d" % (hour, minutes, seconds)
            logging.info("Scan Summary:")
            logging.info(f"\tDuration: {durationStr}")
            logging.info(f'\tTotal Issues: {summary["total_issues"]}')
            logging.info(f'\t\tHigh Issues: {summary["high_issues"]}')
            logging.info(f'\t\tMed Issues: {summary["medium_issues"]}')
            logging.info(f'\t\tLow Issues: {summary["low_issues"]}')
            logging.info("Scan Summary:\n"+json.dumps(summary, indent=2))
        logging.info("========== Step 4: Complete =======================\n")
        

        #Step 5: Download the Scan Report
        logging.info("========== Step 5: Download Scan Report ===========")
        notes = ""
        if(len(repo)>0):
            notes += f"Github Repo: {repo} "
        if(runNum!=0):
            notes += f"Run Number: {runNum}"
        reportFileName = scanName+".html"
        reportPath = os.path.join(reportsDir, reportFileName)
        report = self.getReport(scanId, reportPath, notes)
        if(report is None):
            logging.error("Error downloading report")
            self.fail("Error Running ASoC SAST Pipeline")
            return False
        logging.info(f"Report Downloaded [{reportPath}]")
        logging.info("========== Step 5: Complete =======================\n")
        
        self.success("ASoC SAST Pipeline Complete")
        
    #download and unzip SAClientUtil to {cwd}/saclient
    def getSAClient(self, saclientPath="saclient"):
        #Downloading SAClientUtil
        url = "https://cloud.appscan.com/api/SCX/StaticAnalyzer/SAClientUtil?os=linux"
        logging.info("Downloading SAClientUtil Zip")
        r = requests.get(url, stream=True)
        if(r.status_code != 200):
            logging.error("Invalid HTTP code downloading SAClient Util")
            return False
        file_size = int(r.headers["content-length"])
        disposition = r.headers["content-disposition"]
        chunk_size = 4096
        xfered = 0
        percent = 0
        start = time.time()
        save_path = os.path.join(self.cwd, "saclient.zip")
        with open(save_path, 'wb') as fd:
            for chunk in r.iter_content(chunk_size=chunk_size):
                fd.write(chunk)
                xfered += len(chunk)
                percent = round((xfered/file_size)*100)
                if(time.time()-start > 3):
                    logging.info(f"SAClientUtil Download: {percent}%")
                    start = time.time()
        logging.info(f"SAClientUtil Download: {percent}%")
        
        #Extract the downloaded file
        logging.info("Extracting SAClientUtil Zip")
        with zipfile.ZipFile(save_path, 'r') as zip_ref:
            zip_ref.extractall(saclientPath)

        #Make sure all the SAClientUtil Files can be read and executed
        logging.info("Setting permissions on SACLientUtil Files")
        result = os.system(f"chmod -R 755 {saclientPath}")
        
        if(result == 0):
            logging.info("Successfully set permissions")
        else:
            logging.error("Failed setting permissions")
            return None
            
        #Find the appscan executable
        logging.info("Finding appscan bin path")
        appscanPath = None
        dirs = os.listdir(saclientPath)
        for file in dirs:
            appscanPath = os.path.join(self.cwd, saclientPath, file, "bin", "appscan.sh")
            
        if(os.path.exists(appscanPath)):
            logging.info(f"AppScan Bin Path [{appscanPath}]")
        else:
            logging.error("Something went wrong setting up the SAClientUtil")
            logging.error(f"AppScan Bin [{appscanPath}] not found!")
            return None
        
        #Return the appscan executable path
        return appscanPath
        
    #generate IRX file for target directory
    def genIrx(self, scanName, appscanPath, targetPath, reportsDir, configFile=None):
        #Change Working Dir to the target directory
        logging.info(f"Changing dir to target: [{targetPath}]")
        os.chdir(targetPath)
        logging.info("IRX Gen stdout will be saved to [reports]")
        logging.info("Running AppScan Prepare")
        irxFile = self.asoc.generateIRX(scanName, appscanPath, reportsDir, configFile, self.debug)
        if(irxFile is None):
            logging.error("IRX Not Generated")
            return None
            
        irxPath = os.path.join(targetPath, irxFile)
        logPath = os.path.join(targetPath, scanName+"_logs.zip")
        
        #Change working dir back to the previous current working dir
        logging.info(f"Changing dir to previous working dir: [{self.cwd}]")
        os.chdir(self.cwd)
        
        #Check if logs dir exists, if it does copy to the reports dir to be saved
        if(os.path.exists(logPath)):
            logging.info(f"Logs Found [{logPath}]")
            logging.info("Copying logs to reports dir")
            newLogPath = os.path.join(reportsDir, scanName+"_logs.zip")
            res = shutil.copyfile(logPath, newLogPath)
            if(res):
                logging.info(f"Logs Saved: [{res}]")
                
        #Verify the IRX File Exists
        if(os.path.exists(irxPath)):
            logging.info(f"IRX Path [{irxPath}]")
            return irxPath
        
        logging.error(f"IRX File does not exist [{irxPath}]")
        return None
    
    #Create the SAST scan based on an IRX File
    #If Wait=True the function will sleep until the scan is complete
    def runScan(self, scanName, appId, irxPath, comment="", wait=True):
        #Verify that ASoC is logged in, if not then login
        logging.info("Login to ASoC")
        if(not self.asoc.checkAuth()):
            if(self.asoc.login()):
                logging.info("Successfully logged into ASoC API")
            else:
                logging.error("Error logging into ASoC!")
                return None
               
        #Verify that appId exists
        logging.info(f"Checking AppId [{appId}]")
        app = self.asoc.getApplication(appId)
        if(app):
            appName = app["Name"]
            logging.info("App Found:")
            logging.info(f"\t[{appName}] - [{appId}]")
        else:
            logging.error("Invalid AppId: App Not Found!")
            return None
        
        scanName = appName+"_"+scanName
        #Upload the IRX File and get a FileId
        logging.info("Uploading IRX File")
        fileId = self.asoc.uploadFile(irxPath)
        if(fileId is None):
            logging.error("Error uploading IRX File")
        logging.info(f"IRX FileId: [{fileId}]")
        
        #Run the Scan
        logging.info("Running Scan")
        scanId = self.asoc.createSastScan(scanName, appId, fileId, comment)
        
        if(scanId):
            logging.info("Scan Created")
            logging.info(f"ScanId: [{scanId}]")
        else:
            logging.error("Scan not created!")
            return None
            
        #If Wait=False, return now with scanId
        if(wait == False):
            logging.info("Do not wait for scan to complete, return immediatly")
            return scanId
        
        logging.info("Waiting for scan to complete (status=Ready)")
        status = self.asoc.getScanStatus(scanId)
        c = 0
        start = time.time()
        while(status not in ["Ready", "Abort"]):
            if(time.time()-start >= 120):
                logging.info(f"\tScan still running...(status={status})")
                start = time.time()
            time.sleep(15)
            status = self.asoc.getScanStatus(scanId)
        
        if(status == "Ready"):
            logging.info(f"Scan [{scanId}] Complete")
        else:
            logging.error("ASoC returned an invalid status... check login?")
            logging.error("If script continues, the scan might not be complete")
        return scanId
    
    #Download a report based on a scan
    def getReport(self, scanId, reportPath, note=""):
        reportConfig = {
            "Configuration": {
					"Summary": True,
					"Overview": True,
					"TableOfContent": True,
					"Advisories": True,
					"FixRecommendation": True,
					"MinimizeDetails": True,
					"ReportFileType": "Html",
					"Title": "HCL ASoC SAST Security Report",
                    "Notes": note
				}
        }
        reportId = self.asoc.startReport(scanId, reportConfig)
        if(reportId is None):
            logging.error("Error starting report")
            return None
        
        statusMsg = self.asoc.reportStatus(reportId)
        while(statusMsg["Status"] not in ["Ready", "Abort"]):
            time.sleep(5)
            statusMsg = self.asoc.reportStatus(reportId)
            percent = statusMsg["Progress"]
            logging.info(f"Report Progress: {percent}%")
        
        if(statusMsg["Status"] != "Ready"):
            logging.error("Problem generating report")
            return None
        logging.info("Report Complete, downloading report")
        
        result = self.asoc.downloadReport(reportId, reportPath)
        if(not result):
            logging.error(f"Error Downloading Report")
        return os.path.exists(reportPath)
    
    def getScanSummary(self, scanId, summaryPath):
        summary = self.asoc.scanSummary(scanId)
        if(summary is None):
            logging.error("HTTP Error Code when getting scan summary")
            return None
        summaryDict = {
            "scan_name": summary["Name"],
            "scan_id": summary["Id"],
            "createdAt": summary["LatestExecution"]["ExecutionDurationSec"],
            "duration_seconds": summary["LatestExecution"]["ExecutionDurationSec"],
            "high_issues": summary["LatestExecution"]["NHighIssues"],
            "medium_issues": summary["LatestExecution"]["NMediumIssues"],
            "low_issues": summary["LatestExecution"]["NLowIssues"],
            "info_issues": summary["LatestExecution"]["NInfoIssues"],
            "total_issues": summary["LatestExecution"]["NIssuesFound"],
            "opensource_licenses": summary["LatestExecution"]["NOpenSourceLicenses"],
            "opensource_packages": summary["LatestExecution"]["NOpenSourcePackages"]
        }
        logging.info(f"Scan summary saved [{summaryPath}]")
        with open(summaryPath, "w") as summaryFile:
            json.dump(summary, summaryFile, indent=4)
        return summaryDict
    
    #Get current system timestamp
    def getTimeStamp(self):
        ts = time.time()
        return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d_%H-%M-%S')
    
    def fail(self, messag=""):
        logging.info(f"Action Failed: {message}")
        sys.exit(1)
        
    def success(self, message=""):
        logging.info(f"Action Success: {message}")
        
if __name__ == '__main__':
    action = AppScanOnCloudSAST()
    action.run()
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
