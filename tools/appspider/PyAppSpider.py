import json
import requests
import requests.exceptions
import requests.packages.urllib3
from xml.etree import cElementTree as ET

#from . import __version__ as version

class PyAppSpider(object):
    """An API wrapper for AppSpider Enterprise.
    https://appspider.help.rapid7.com/docs/rest-api-overview
    """

    token = None
    success = False
    loginCode = 0
    clients = None

    def __init__(self, host, api_version='v1', verify_ssl=True, timeout=60, proxies=None, user_agent=None, cert=None, debug=False):
        """Initialize a AppSpider Enterprise API instance.

        :param host: The URL for the AppSpider Enterprise server. (e.g., http://localhost:8000/AppSpider Enterprise/)
        :param api_key: The API key generated on the AppSpider Enterprise API key page.
        :param user: The user associated with the API key.
        :param api_version: API version to call, the default is v1.
        :param verify_ssl: Specify if API requests will verify the host's SSL certificate, defaults to true.
        :param timeout: HTTP timeout in seconds, default is 30.
        :param proxies: Proxy for API requests.
        :param user_agent: HTTP user agent string, default is "AppSpider Enterprise_api/[version]".
        :param cert: You can also specify a local cert to use as client side certificate, as a single file (containing
        the private key and the certificate) or as a tuple of both file's path
        :param debug: Prints requests and responses, useful for debugging.

        """
        version = "0.2"
        self.host = host + 'AppSpiderEnterprise/rest/' + api_version + '/'
        self.api_version = api_version
        self.verify_ssl = verify_ssl
        self.proxies = proxies
        self.timeout = timeout

        if not user_agent:
            self.user_agent = 'pyAppSpider_api/v' + version
        else:
            self.user_agent = user_agent

        self.cert = cert
        self.debug = debug  # Prints request and response information.

        token = None
        if not self.verify_ssl:
            requests.packages.urllib3.disable_warnings()  # Disabling SSL warning messages if verification is disabled.

    def authenticate(self, name, password, clientId=None):
        """Returns the AppSpider authentication token and/or client associated with the login. If the account is multi-client then AppSpider returns the list of clients associated with the account.

        :param name: Userid of the appspider user
        :param name: Password of the appspider user
        :param name: ClientID in AppSpider

        """
        params  = {}

        if clientId:
            params['clientId'] = clientId

        params['name'] = name
        params['password'] = password

        response = self._request('POST', 'Authentication/Login', data=params)

        if response.success:
            self.success = response.data["IsSuccess"]
            if self.success:
                self.token = response.data["Token"]
                self.loginCode = 1 #Authenticated
            elif response.data["Reason"] == "Invalid clientId":
                self.clients = response.data["Clients"]
                self.loginCode = 2 #Authenticated but need to select a client id
        else:
            #Connection error or bad login
            self.success = False

        return response

    ###### Helper Functions ######

    def get_client_name(self, clientId):
        """Retrieves the client name from a client id

        :param clientId: Client ID (guid)

        """

        config = self.get_config(clientId)

        return config.json()["Config"]["Name"]

    def get_scan_status_text(self, statusId):
        """Retrieves the client name from a client id

        :param clientId: Status ID (int)

        """
        statusTxt = "Unknown Code: " + str(statusId)
        if statusId == 32:
            statusTxt = "Completed"
        elif statusId == 72:
            statusTxt = "Failed"
        elif statusId == 80:
            statusTxt = "Paused"
        elif statusId == 82:
            statusTxt = "Running"
        elif statusId == 119:
            statusTxt = "Vuln Load Failed"
        elif statusId == 122:
            statusTxt = "Stopping"

        return statusTxt

    def edit_scan_config_xml(self, xml_file, seed_urls, scope_constraints, custom_headers):
        """Adds xml elements for scanning url and includes

        :param xml_file: Scanner config xml file
        :param seed_urls: seed_url
        :param scope_constraints: scope_constraints

        """

        tree = ET.parse(xml_file)

        xmlRoot = tree.getroot()
        xml_node = xmlRoot.findall("CrawlConfig/SeedUrlList")

        for elem in xmlRoot.iterfind('CrawlConfig/SeedUrlList'):
            for seed_url in seed_urls:
                seedUrl = ET.Element("SeedUrl")
                elem.append(seedUrl)
                value = ET.Element("Value")
                value.text = seed_url['url']
                seedUrl.append(value)

        for elem in xmlRoot.iterfind('CrawlConfig/ScopeConstraintList'):
            for scope_constraint in scope_constraints:
                scope_constraintXML = ET.Element("ScopeConstraint")
                elem.append(scope_constraintXML)
                #URL
                url = ET.Element("URL")
                url.text = scope_constraint['url']
                scope_constraintXML.append(url)
                #Method
                method = ET.Element("Method")
                if 'method' in scope_constraint:
                    method.text = scope_constraint['method']
                else:
                    method.text = "All"
                scope_constraintXML.append(method)
                #MatchCriteria
                match_criteria = ET.Element("MatchCriteria")
                if "match_criteria" in scope_constraint:
                    match_criteria.text = scope_constraint["match_criteria"]
                else:
                    match_criteria.text = "Wildcard"

                scope_constraintXML.append(match_criteria)
                #Exclusion
                include = ET.Element("Exclusion")
                if "include" in scope_constraint:
                    include.text = scope_constraint["include"]
                else:
                    include.text = "Include"

                scope_constraintXML.append(include)
                http_param = ET.Element("HttpParameterList")
                scope_constraintXML.append(http_param)

        #Add a customer header, like an API token
        for elem in xmlRoot.iterfind('HTTPHeadersConfig/CustomHeadersList'):
            for custom_header in custom_headers:
                customHeaders = ET.Element("CustomHeaders")
                elem.append(customHeaders)
                value = ET.Element("Value")
                value.text = custom_header["custom_header"]
                customHeaders.append(value)

        return ET.tostring(xmlRoot, method="xml")

    #Saves a file from string
    def save_file(self, data, filename):
        success = None
        #If the API can't find the file it returns a json object
        if "IsSuccess" in data:
            success = False
        else:
            file = open(filename,"wb")
            file.write(data)
            file.close
            success = True

        return success

    ###### Scan API #######

    ###### Scan Management ######
    def get_scans(self):
        """Retrieves the list of scans.

        """

        return self._request('GET', "Scan/GetScans")

    def run_scan(self, configId=None, configName=None):
        """Starts a scan. At least one parameter should be provided to start a scan

        :param configId: Scan config ID (guid)
        :param configName: Scan config name

        """
        params  = {}
        if configId:
            params['configId'] = configId

        if configName:
            params['configName'] = configName

        return self._request('POST', "Scan/RunScan/", data=params)

    def cancel_scan(self, scanId):
        """Cancels "Starting" or "Waiting for Cloud" scan

        :param scanId: Scan ID (guid)

        """

        params  = {}
        params['scanId'] = scanId

        return self._request('POST', "/Scan/CancelScan", data=params)

    def pause_scan(self, scanId):
        """Pauses a running scan

        :param scanId: Scan ID (guid)

        """

        params  = {}
        params['scanId'] = scanId

        return self._request('POST', "/Scan/PauseScan", data=params)

    def pause_all_scans(self):
        """Pauses all running scans


        """

        return self._request('POST', "/Scan/PauseAllScans")

    def resume_scan(self, scanId):
        """Resumes a scan

        :param scanId: Scan ID (guid)

        """

        params  = {}
        params['scanId'] = scanId

        return self._request('POST', "/Scan/ResumeScan", data=params)

    def resume_all_scans(self):
        """Resumes all scans


        """

        return self._request('POST', "/Scan/ResumeAllScans")

    def stop_scan(self, scanId):
        """Stops a running scan

        :param scanId: Scan ID (guid)

        """

        params  = {}
        params['scanId'] = scanId

        return self._request('POST', "/Scan/StopScan", data=params)

    def stop_all_scans(self):
        """Stops all scans


        """

        return self._request('POST', "/Scan/StopAllScans")

    def get_scan_status(self, scanId):
        """Retrieves the scan status represented by a string

        :param scanId: Scan ID (guid)

        """

        params  = {}
        params['scanId'] = scanId

        return self._request('GET', "Scan/GetScanStatus", params)

    def is_scan_active(self, scanId):
        """Checks to see if the specified scan is active

        :param scanId: Scan ID (guid)

        """

        params  = {}
        params['scanId'] = scanId

        return self._request('GET', "Scan/IsScanActive", params)

    def is_scan_finished(self, scanId):
        """Checks to see if the specified scan is finished

        :param scanId: Scan ID (guid)

        """

        params  = {}
        params['scanId'] = scanId

        return self._request('GET', "Scan/IsScanFinished", params)

    def scan_has_report(self, scanId):
        """Checks to see if the specified scan has a report

        :param scanId: Scan ID (guid)

        """

        params  = {}
        params['scanId'] = scanId

        return self._request('GET', "Scan/HasReport", params)

    ###### Finding API #######
    def get_vulnerabilities(self):
        """Retrieves the list of vulnerabilities filtered by the specified parameters.

        """

        return self._request('GET', "Finding/GetVulnerabilities")

    ###### Scan Engine Operations #######
    def admin_get_engines(self):
        """Retrieves the list of scan engines.

        """

        return self._request('GET', "Engine/GetEngines")

    def admin_save_engine(self, url, virtualName, login, password, id=None, notes=None, doNotUpdate=None):
        """Creates or updates scan engine

        :param id: if id not provided new engine will be created. if id provided engine update performed.
        :param url: Scan engine URL. URL scheme should be {scheme}://{domain}/{path}/default.asmx
        :param virtualName: Scan engine name
        :param login: Scan engine username
        :param notes: Notes
        :param doNotUpdate: Do not update engine property

        """

        params  = {}

        params['url'] = url
        params['virtualName'] = virtualName
        params['login'] = login
        params['password'] = password

        if id:
            params['id'] = id

        if notes:
            params['notes'] = notes

        if doNotUpdate:
            params['doNotUpdate'] = doNotUpdate

        return self._request('POST', "Engine/SaveEngine", params)

    def admin_delete_engine(self, ids):
        """Scan engine IDs

        :param ids: Scan Engine ID (guid)

        """
        params['ids'] = ids

        return self._request('POST', "Engine/DeleteEngine", params)

    ###### Scan Engine Operations #######
    def admin_get_all_engine_groups(self):
        """Retrieves the list of scan engine groups. Note that System Administrator credentials are required to work with scan engines

        """

        return self._request('GET', "EngineGroup/GetAllEngineGroups")

    def admin_get_engine_groups_for_client(self):
        """Retrieves the list of scan engine groups for a client. Note that System Administrator credentials are required to work with scan engines

        """

        return self._request('GET', "EngineGroup/GetEngineGroupsForClient")

    def admin_save_engine_group(self, name, description=None, monitoring=None, id=None):
        """Creates or updates a scan engine group

        :param id: If id not provided a new engine group will be created. If an id is provided then an engine group update is performed.
        :param name: Scan engine group name. Name should be unique
        :param description: Scan engine group description
        :param monitoring: Scan engine group is monitoring

        """

        params  = {}

        params['name'] = name

        if id:
            params['id'] = id

        if description:
            params['description'] = description

        if monitoring:
            params['monitoring'] = monitoring

        return self._request('POST', "EngineGroup/SaveEngineGroup", data=params)

    def admin_delete_engine_group(self, ids):
        """Deletes a scan engine group

        :param ids: Scan engine group IDs (guid)

        """

        params  = {}

        params['ids'] = ids

        return self._request('POST', "EngineGroup/DeleteEngineGroup", data=params)

    def admin_add_engine_to_group(self, groupId, engineId):
        """Adds a scan engine to a scan engine group

        :param groupId: Scan engine group ID
        :param engineId: Scan engine ID

        """

        params  = {}

        params['groupId'] = groupId
        params['engineId'] = engineId

        return self._request('POST', "EngineGroup/AddEngineToGroup", data=params)

    def admin_delete_engine_from_group(self, groupId, engineId):
        """Deletes scan engine from scan engine group

        :param groupId: Scan engine group ID
        :param engineId: Scan engine ID

        """

        params  = {}

        params['groupId'] = groupId
        params['engineId'] = engineId

        return self._request('POST', "EngineGroup/DeleteEngineFromGroup", data=params)

    ###### Report Management #######
    def import_standard_report(self, reportData, scanId=None, configId=None):
        """Creates a new scan in the scan history or updates the report for the specified scan

        :param scanId: Update scan report if scanId provided and create new scan details if not
        :param reportData: Report file
        :param configId: Config id uploaded report attached to

        """

        params  = {}

        params['reportData'] = reportData

        if scanId:
            params['scanId'] = scanId

        if configId:
            params['configId'] = configId

        return self._request('POST', "Report/ImportStandardReport", data=params)

    def import_checkmarx_report(self, scanId, file):
        """Creates a new scan in the scan history or updates the report for the specified scan

        :param scanId: Scan ID
        :param file: Checkmarx report XML file

        """

        params  = {}

        params['scanId'] = scanId
        params['file'] = file

        return self._request('POST', "Report/ImportCheckmarxReport", data=params)

    def get_vulnerabilities_summary(self, scanId):
        """Gets VulnerabilitiesSummary.xml for the scan. Only scans in "Completed" and "Stopped" states may have a report

        :param scanId: Scan ID

        """

        params  = {}

        params['scanId'] = scanId

        return self._request('GET', "Report/GetVulnerabilitiesSummaryXml", params)

    def get_report_zip(self, scanId):
        """Gets ReportAllFiles.zip for the scan. Only scans in "Completed" and "Stopped" states may have reports

        :param scanId: Scan ID

        """

        params  = {}

        params['scanId'] = scanId

        return self._request('GET', "Report/GetReportZip", params)

    def get_crawled_links(self, scanId):
        """Gets CrawledLinks.xml for the scan. Only scans in "Completed" and "Stopped" states may have a report

        :param scanId: Scan ID

        """

        params  = {}

        params['scanId'] = scanId

        return self._request('GET', "Report/GetCrawledLinksXml", params)

    ###### Scan Configuration Operations #######
    def save_config(self, xml, name, engineGroupId, clientId, id=None, defendEnabled=False, monitoring=False,
        monitoringDelay=0, monitoringTriggerScan=False, isApproveRequired=False, seed_url=False, constraint_url=False,
        seed_urls=False, scope_constraints=False, custom_headers=False):
        """Creates a new scan configuration

        :param id: If id not provided new config will be created. If id provided config update performed.
        :param xml: Scan config xml file. Config name should be unique in the client.
        :param defendEnabled: AppSpider Defend enabled
        :param monitoring: Monitoring scanning enabled
        :param monitoringDelay: Delay between monitoring scans in hours. Possible values are 1 (hour), 24 (day), 168 (week), 720 (month)
        :param monitoringTriggerScan: Monitoring scan triggers attack scan if changes found
        :param name: Config name
        :param engineGroupId: Engine group id for scan config
        :param isApproveRequired: Approve required property

        """

        params  = {}

        #Required Parameters
        params['Name'] = name
        params['EngineGroupId'] = engineGroupId
        params['ClientId'] = clientId

        #Not required parameters
        params['Id'] = id
        params['DefendEnabled'] = defendEnabled
        params['Monitoring'] = monitoring
        params['MonitoringDelay'] = monitoringDelay
        params['MonitoringTriggerScan'] = monitoringTriggerScan
        params['IsApproveRequired'] = isApproveRequired

        #XML Scan Config Parameters
        params['Xml'] = self.edit_scan_config_xml(xml, seed_urls, scope_constraints, custom_headers)

        return self._request('POST', "Config/SaveConfig", files={'Config': (None,json.dumps(params))})

    def get_configs(self):
        """Retrieves all scan configs for the client

        """

        return self._request('GET', "Config/GetConfigs")

    def get_config(self, id):
        """Retrieves scan config for the client

        :param id: Scan config ID

        """

        params  = {}

        params['id'] = id

        return self._request('GET', "Config/GetConfig", params)

    def get_attachment(self, configId, fileName, fileType):
        """Retrieves auxiliary files (such as macro, traffic recording, etc), referenced in the scan configuration

        :param configId: Scan config ID
        :param fileName: Name of requested file
        :param fileType: File type. Values are: "Authentication", "Certificate", "Crawling", "Selenium", "Traffic", "Wsdl

        """

        params  = {}

        params['configId'] = configId
        params['fileName'] = fileName
        params['fileType'] = fileType

        return self._request('POST', "Config/GetAttachment", data=params)

    ###### Blackout Operations Operations #######
    def get_blackouts(self):
        """Retrieves the blackout list for the client


        """

        return self._request('GET', "Blackout/GetBlackouts")

    def save_blackout(self, name, startTime, targetHost, id=None, stopTime=None, isRecurring=None, recurrence=None):
        """Creates or updates a blackout window

        :param name: Blackout name. Name should be unique in the client
        :param startTime: Date and time the blackout starts
        :param targetHost: Name of host for the blackout
        :param id: Blackout id. Update blackout if id provided and create new blackout if not provided
        :param stopTime: Date and time the blackout ends
        :param isRecurring: Marks the blackout as a reoccurring event
        :param recurrence: Sets the recurrence frequency. See the section "Recurrences Explained" for more detail.

        """

        params  = {}

        params['name'] = name
        params['startTime'] = startTime
        params['targetHost'] = targetHost

        if id:
            params['id'] = id

        if stopTime:
            params['stopTime'] = id

        if isRecurring:
            params['isRecurring'] = id

        if recurrence:
            params['recurrence'] = id

        return self._request('POST', "Blackout/SaveBlackout", data=params)

    def delete_blackouts(self, blackoutIds):
        """Removes a blackout window

        :param blackoutIds: Scan config ID

        """

        params  = {}

        params['blackoutIds'] = blackoutIds

        return self._request('POST', "Blackout/DeleteBlackouts", data=params)


    # Utility
    @staticmethod
    def _build_list_params(param_name, key, values):
        """Builds a list of POST parameters from a list or single value."""
        params = {}
        if hasattr(values, '__iter__'):
            index = 0
            for value in values:
                params[str(param_name) + '[' + str(index) + '].' + str(key)] = str(value)
                index += 1
        else:
            params[str(param_name) + '[0].' + str(key)] = str(values)
        return params

    def _request(self, method, url, params=None, data=None, files=None):
        """Common handler for all HTTP requests."""
        if not params:
            params = {}

        if data:
            data = json.dumps(data)

        headers = {
            'User-Agent': self.user_agent,
            'Authorization': 'Basic ' + str(self.token)
        }

        if not files:
            headers['Accept'] = 'application/json'
            headers['Content-Type'] = 'application/json'

        if self.proxies:
            proxies=self.proxies
        else:
            proxies = {}

        try:
            if self.debug:
                print(method + ' ' + url)
                print(params)

            response = requests.request(method=method, url=self.host + url, params=params, data=data, files=files, headers=headers,
                                        timeout=self.timeout, verify=self.verify_ssl, cert=self.cert, proxies=proxies)

            if self.debug:
                print(response.status_code)
                print(response.text)

            try:
                if response.status_code == 201: #Created new object
                    data = response.json()

                    return AppSpiderResponse(message="Upload complete", data=data, success=True)
                elif response.status_code == 204: #Object updates
                    return AppSpiderResponse(message="Object updated.", success=True)
                elif response.status_code == 404: #Object not created
                    return AppSpiderResponse(message="Object id does not exist.", success=False)
                elif 'content-disposition' in response.headers:
                    data = response.content
                    return AppSpiderResponse(message="Success", data=data, success=True, response_code=response.status_code)
                else:
                    data = response.json()
                    return AppSpiderResponse(message="Success", data=data, success=True, response_code=response.status_code)
            except ValueError as e:
                return AppSpiderResponse(message='JSON response could not be decoded. Detailed error: ' + str(e), success=False)
        except requests.exceptions.SSLError as e:
            return AppSpiderResponse(message='An SSL error occurred. Detailed error: ' + str(e), success=False)
        except requests.exceptions.ConnectionError as e:
            return AppSpiderResponse(message=str(e) + 'A connection error occurred. Detailed error: ' + str(e), success=False)
        except requests.exceptions.Timeout as e:
            return AppSpiderResponse(message='The request timed out after ' + str(self.timeout) + ' seconds.',
                                     success=False)
        except requests.exceptions.RequestException as e:
            return AppSpiderResponse(message='There was an error while handling the request. Detailed error: ' + str(e), success=False)


class AppSpiderResponse(object):
    """
    Container for all AppSpider Enterprise API responses, even errors.

    """

    def __init__(self, message, success, data=None, response_code=-1):
        self.message = message
        self.data = data
        self.success = success
        self.response_code = response_code

    def __str__(self):
        if self.data:
            return str(self.data)
        else:
            return self.message

    def binary(self):
        return self.data

    def json(self):
        return self.data

    def id(self):
        if self.response_code == 400: #Bad Request
            raise ValueError('Object not created:' + json.dumps(self.data, sort_keys=True, indent=4, separators=(',', ': ')))
        return int(self.data)

    def count(self):
        return self.data["TotalCount"]

    def is_success(self):
        data = None

        try:
            data = self.data["IsSuccess"]
        except:
            data = self.data

        return data

    def error(self):
        errorMessage = self.message

        if self.data is not None:
            if "ErrorMessage" in self.data:
                self.data["ErrorMessage"]

        return errorMessage

    def data_json(self, pretty=False):
        """Returns the data as a valid JSON string."""
        if pretty:
            return json.dumps(self.data, sort_keys=True, indent=4, separators=(',', ': '))
        else:
            return json.dumps(self.data)
