pushd ms-matrix
git clone https://github.com/microsoft/Azure-Threat-Research-Matrix.git
popd

CALL pipenv install
mkdir build
CALL pipenv run python ./src/parse.py