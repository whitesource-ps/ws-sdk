REM Script to redeploy ws-sdk during development
cd C:\GIT\whitesource-ps\ws-sdk
pip uninstall -y ws-sdk
python setup.py develop --user
pip install .\dist\ws-sdk-*.whl
