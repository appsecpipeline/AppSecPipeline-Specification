echo "Building Jenkins Jobs"
sh jenkins.sh
echo
echo "Creating global tool yaml"
python build/combine-yaml.py
echo "Complete\n"
