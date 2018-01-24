import os
import yaml

secPipelineFile = "controller/secpipeline-config.yaml"

def createSecPipeLine():
    #Re-create the pipeline config file
    os.remove(secPipelineFile)

    for subdir, dirs, files in os.walk("tools"):
        for file in files:
            if file.lower().endswith("yaml"):
                yamlFile = os.path.join(subdir, file)

                #Read tool YAML
                with open(yamlFile, 'r') as toolYaml:
                    yamlContent = toolYaml.read()

                #Write to secpipeline-config.yaml
                with open(secPipelineFile, 'a+') as file:
                    file.write(yamlContent)

def quoted_presenter(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='"')

yaml.add_representer(str, quoted_presenter)

def readYAML():
    #Read tool YAML
    with open(secPipelineFile, 'r') as stream:
        try:
            tools = yaml.safe_load(stream)
            data = {}
            parameters = {}
            parameters_details = {}

            for tool in tools:
                toolParms = tools[tool]["parameters"]
                parameters_key = {}
                for parameter in toolParms:
                    if toolParms[parameter]["type"] == "config":
                        parameters_key["type"] = toolParms[parameter]["type"]
                        parameters_key["data_type"] = toolParms[parameter]["data_type"]
                        parameters_key["description"] = toolParms[parameter]["description"]
                        parameters_key["value"] = '{replace-me}'
                        parameters_details[parameter] = parameters_key
                        parameters_key = {}

                if parameters_details:
                    parameters["parameters"] = parameters_details
                    data[tool] = parameters

                parameters = {}
                parameters_details = {}

            yamlLoc = "controller/tool-config-template.config"
            with open(yamlLoc, 'w') as outfile:
                yaml.dump(data, outfile, default_flow_style=False)

        except yaml.YAMLError as exc:
            print(exc)


createSecPipeLine()
readYAML()
print "Complete!"
