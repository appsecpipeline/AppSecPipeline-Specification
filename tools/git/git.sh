action=$1
repo=$2
dest=$3
tag=$4

git clone $repo $dest
cd $dest

if [ $action = "tag" ]; then
  git fetch --all
  git checkout $4
fi
