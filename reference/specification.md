## AppSec Pipeline Specification

Version: 1.0

### Key Components of an AppSec Pipeline

To set the terminology used in this specification, the following AppSec specific terms will be defined as they are used within this specification.

* _Event_ - something that causes a run of an AppSec Pipeline
* * e.g. code commit, webhook, compliance schedule, feature release, ...
* _Controller_ - the main application implemented in any language which orchestrates creation and running of AppSec Pipelines
* _Tool(s), Tools Container_ - A Linux container which has 1 or more security assessment tool installed along with additional AppSec Pipeline software (Casper)
* * e.g. appsecpipeline/sast:1.0, appsecpipeline/zap:1.0, ...
* _Target_ - something being tested by a tool, typically a container which has source for static tools to test or a running app for dynamic tools to test.
* _Results Volume_ - a data container where the results of a specific tool is stored for the duration of a pipeline run.  In the case of static testing, the source code may also be located on the results volume. Results volumes are ephemeral and deleted by the end of a pipeline run.
* _Persistent Volume_ - a location where, optionally, all results from every pipeline run are stored for archival purposes.
* _Named Pipeline_ - A run of the AppSec Pipeline that follows a labeled workflow which has 1+ tools specified 
* * e.g. a Pipeline labeled "python-sast" could run bandit, flake8 and other Python tools against a target
* _SAST run_ - A pipeline run whose target is an application's code base
* _DAST run_ - A pipeline run whose target is a running application
* Vulnerability Repository - a location where all the issues found by a pipeline run are stored for reporting, metrics and other purposes.
* _Pipeline Item_ - An item of work in the AppSec Pipeline done by a specified container image to achieve a goal
* * e.g. Run a tool against a target, clone source from a Git repo, submit results to the REST API of a vuln repository, transform tool output to a usable format, ...

### Key states of AppSec Pipelines

* _Initialization_ - the early stage of starting a controller to run AppSec Pipelines where configuration is read and needed container images are inventoried and downloaded as needed.
* _Ready_ - the controller has all configuration data needed to begin launching named pipeline runs based on events.
* _Shutdown_ - the controller optionally waits for all pipeline runs to complete and frees all resources before exiting.

After an event occurs, the AppSec Pipeline will follow the following stages for each named pipeline run:

1. Startup - run 0 or more containers prior to the pipeline run
* * Launch any needed containers such as a results volume, target, etc.
* * For SAST runs, 
* * * Cloning the source locally may optionally be done
* * * Checking the source code for an appsec.pipeline file 
* * For DAST runs,
* * * Checking the availability and connectivity of the target (optional)
* * * Verifying the credentials (if provided) for the target (optional)
1. Pipeline - run 1 or more tool containers against a target
* * For each step in the pipeline
* * * Launch the tool container, passing in parameters for this instance
* * * * Mount the results volume during launch
* * * Run the tool against the target per the selected profile
* * * Write tool results to the results volume
* * * Upload results to the Vulnerability repository (optional)
* * * Send controller 'Completed' webhook 
1. Final - run 0 or more containers after the pipeline run
* * Launch any needed containers to do any final data processing or uploads of results
* * * e.g. Launch a program to convert output of tool(s) to a supported import format
1. Cleanup
* * Launch a container to push raw tool results to the persistent volume (optional)
* * Destroy any container used by this pipeline run
* * Destroy the results volume

#### To be documented

* Logging requirements
* Notification requirements

### AppSec Pipeline - Detailed Specification 

Note: Where possible, a reference to the sequence diagram (pipeline-static.png) will be provided in the specification below to provide a cross-reference between the spec and the diagram.  The sequence diagram step numbers will be added at the end of a line in {} braces like {01}.

#### Initialization

* Read configuration files {01}
* * Requires: Path to configuration files (single location as base for all config files)
* * Files
* * * master.yaml - global configuration and named pipeline tool configurations {02}
* * * secpipeline-config.yaml - list of tools, their container names + version and profiles to run the tool {03}
* * Set needed data structures to use for pipeline runs
* Ensure needed container images are available
* * Request a list of available images from configured image repository {04}
* * Diff available images to those listed in secpipeline-config.yaml
* * For any missing images, pull them into the image repo {06}

#### Events

Currently, event types are not well specified but for an event to cause a pipeline run, the following data is required:

* profile - string: named pipeline from master.yaml, appsec.pipeline or {app name}-pipeline.yaml
* app_name - string: name of the app being tested, for human friendly logging
* event_type - string: type of event that caused the named pipeine run e.g. command-line, git commit
* pipeline_type - string: type of pipeline run, currently either "static" or "dynamic"

The data below have defaults and are only required if a non-default value is desired

* dry_run - boolean: default = false - Do this pipeline run without launching actual dockers, etc
* persist_containers - boolean: default = false - Keep the containers and volumes once a pipeline run in completed
* app_profile - string: default = "" - application specific pipeline profile to run - usually sent in as a file named {app-name}-pipeline.yaml
* app_tool_profile - string: default = "" - application specific tool profile to run - usually sent in as a file named {app-name}-tool.yaml
* target_container - string: default = "" - name of the Docker container which has the target source or running instance
* local_path - string: default = "" - path to the local directory which contains an apps source code

Events can be as simple as a command line invocation to something as complex as a worker process pulling events off a message queue.  At this time, we're leaving this area open and collecting real world event types to document in future.  At this time, event data can be gathered from the items below listed in diminishing precedence. e.g. environmental variables will override config values.

* Command-line options
* Environmental Variables
* Configuration values
* key/value stores (Redis, etcd, ...) - optional
* defaults (where defined)

In the sequence diagram, events occur at {08}

#### Named Pipeline run

Assuming a event has occurred and the necessary data is available, the controller will start a pipeline run following the four stages outlined above: Startup, Pipeline, Final, Cleanup

Prior to startup, the following will need to occur

* Take the pipeline name/label from the event and match it with ones provided by master.yaml
* Generate a UUID to use as a unique name for this pipeline run
* Based on the chosen pipeline name, then do the steps below as outline in that named pipeline.

##### Startup

Note: Startup is optional and must contain 0 or more items to run

* Launch Target
* * SAST Run
* * * Launch target volume for source code {09}
* * * * If needed, pull code into target volume from source repository
* * * Launch results volume (optionally share single volume for results and source) {11}
* * * Check for the presence of appsec.pipeline in root of source repo {13}
* * * * If present, parse appsec.pipeline and override profile from master.yaml {15}
* * * If needed, run any startup items provided in the appsec.pipeline file {16}
* * DAST Run
* * * Launch target volume for running app (optional - may be available on network already)
* * * Launch results volume

##### Pipeline (call this Tools? over Pipeline to avoid confusion?  Something else?)

For each item in the list of 1+ pipeline items:

* Launch the specified tool container {17}
* * Required data to pass to container
* * * TBD
* * Mount results volume on tool container {18}
* * * Mount point: /opt/appsecpipeline/results
* Run tool against target using the provided command in the selected tool profile {20}
* * Output of tool is handled as needed by options specified in the tool profile {21}
* Upload results of single tool run to Vuln Repository (optional) {22}
* * Use REST API to push results of a single tool run to Vuln repo
* Send "Completed" Webhook to controller {23}
* * Webhook is a POST containing
* * * TBD

##### Final

Note: Final is optional and must contain 0 or more items to run

* Launch results submitter container (if not done above with each tool run) {24}
* * Required data to pass to container
* * * TBD
* Run any other specified items from the named pipeline

##### Cleanup

* Destroy all tool containers used in this named pipeline run
* * List running containers and filter for those with the runs UUID
* * Destroy any matching containers
* Destroy any target containers used in this run (only needed when optional target containers are deployed)
* Persist results to the persistent volume
* * Launch archiver container with results volume mounted
* * Push results to persistent volume (exact method depends on implementation)
* * Destroy archiver container
* Destroy results volume for this named pipeline run

## Appendix

Constants, conventions and other fixed values in the AppSec Pipeline:

* Results volume mount point in tool containers:
* * /opt/appsecpipeline/results
* Subdirectory for each tools results:
* * {UUID}_{toolname}
* * * If multiple runs of same tool, append "-###" to the name starting with -001 for the first match
* Mount point for source code during SAST runs:
* * /opt/appsecpipeline/source
* ID of the default user for AppSec Pipeline docker images:
* * 1337
* Name of the default user for AppSec Pipeline docker images:
* * appsecpipeline
* Naming scheme for containers launched during a pipeline run
* * {UUID}_tool-name for tool containers
* * {UUID}_results for results containers
* * {UUID}_target-name for target containers

Conventions for creating AppSec Pipeline Docker images:

* TBD
* Needs to include launch.py
* Probably should have unified base image if possible

Conventions used when using Defect Dojo as the Vulnerability Repository:

* Each named pipeline run is an unique engagement in Dojo
* * Within the engagement, each tool run is a separate test within that engagement
* TBD
	//	DojoHost    string   // Required - host name of the Dojo instance to push the run restults to
	//	DojoApiKey  string   // Required - API key to talk to Dojo's REST API
	//	DojoProdId  string   // Required - The Product ID from Dojo to submit the results for this test run
	//	//DojoNewEng boot // default = true - Create a new engagement for each pipeline run?
