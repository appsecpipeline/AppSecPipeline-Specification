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

* TBD1
* TBD2

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
* Based on the chosen pipeline name, then do the steps below as outline in that named pipeline.

##### Startup

Note: Startup is optional and must contain 0 or more items to run

* TBD

##### Pipeline

* TBD

##### Final

Note: Final is optional and must contain 0 or more items to run

* TBD

##### Cleanup

* TBD
