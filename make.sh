pushd ms-matrix
git clone https://github.com/aw350m33d/Azure-Threat-Research-Matrix.git
popd

pipenv install
mkdir build
pipenv run python ./src/parse.py